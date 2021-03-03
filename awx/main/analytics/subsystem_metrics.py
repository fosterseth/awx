import redis
import json
import time
import logging

from django.conf import settings
from django.apps import apps
from awx.main.consumers import emit_channel_notification

root_key = 'awx_metrics'
send_metrics_interval = 3 # minimum time that must elapse between sending metrics
logger = logging.getLogger('awx.main.wsbroadcast')


class BaseM():
    def __init__(self, field, help_text):
        self.field = field
        self.help_text = help_text

    def decode(self, conn):
        value = conn.hget(root_key, self.field)
        return self.decode_value(value)

    def set(self, value, conn):
        conn.hset(root_key, self.field, value)

    def to_prometheus(self, instance_data):
        output_text = f"# HELP {self.field} {self.help_text}\n# TYPE {self.field} gauge\n"
        for instance in instance_data:
            output_text += f'{self.field}{{node="{instance}"}} {instance_data[instance][self.field]}\n'
        return output_text


class FloatM(BaseM):
    def inc(self, value, conn):
        conn.hincrbyfloat(root_key, self.field, value)

    def decode_value(self, value):
        if value is not None:
            return float(value)
        else:
            return 0.0


class IntM(BaseM):
    def inc(self, value, conn):
        conn.hincrby(root_key, self.field, value)

    def decode_value(self, value):
        if value is not None:
            return int(value)
        else:
            return 0


class HistogramM(BaseM):
    def __init__(self, field, help_text, buckets):
        self.buckets = buckets
        self.buckets_to_keys = {}
        for b in buckets:
            self.buckets_to_keys[b] = IntM(field + '_' + str(b), '')
        self.inf = IntM(field + '_inf', '')
        self.sum = IntM(field + '_sum', '')
        super(HistogramM, self).__init__(field, help_text)

    def observe(self, value, conn):
        for b in self.buckets:
            if value <= b:
                self.buckets_to_keys[b].inc(1, conn)
                break
        self.sum.inc(value, conn)
        self.inf.inc(1, conn)


    def decode(self, conn):
        values = {'counts':[]}
        for b in self.buckets_to_keys:
            values['counts'].append(self.buckets_to_keys[b].decode(conn))
        values['sum'] = self.sum.decode(conn)
        values['inf'] = self.inf.decode(conn)
        return values

    def to_prometheus(self, instance_data):
        output_text = f"# HELP {self.field} {self.help_text}\n# TYPE {self.field} histogram\n"
        for instance in instance_data:
            for i, b in enumerate(self.buckets):
                output_text += f'{self.field}_bucket{{le="{b}",node="{instance}"}} {sum(instance_data[instance][self.field]["counts"][0:i+1])}\n'
            output_text += f'{self.field}_bucket{{le="+Inf",node="{instance}"}} {instance_data[instance][self.field]["inf"]}\n'
            output_text += f'{self.field}_count{{node="{instance}"}} {instance_data[instance][self.field]["inf"]}\n'
            output_text += f'{self.field}_sum{{node="{instance}"}} {instance_data[instance][self.field]["sum"]}\n'
        return output_text


class Metrics():
    def __init__(self, conn = None):
        if conn is None:
            self.conn = redis.Redis.from_url(settings.BROKER_URL)
            self.conn.client_setname("subsystem_metrics")
        else:
            self.conn = conn

        Instance = apps.get_model('main', 'Instance')
        instance_name = Instance.objects.me().hostname
        self.instance_name = instance_name

    def inc(self, field, value, conn = None):
        if value != 0:
            if conn is None:
                conn = self.conn
            METRICS[field].inc(value, conn)
            self.send_metrics()

    def set(self, field, value, conn = None):
        # conn here could be a pipeline(), so we must get a new conn to do the
        # previous value lookup. Otherwise the hget() won't execute until
        # pipeline().execute is called in the calling function.
        with self.conn as inner_conn:
            previous_value = METRICS[field].decode(inner_conn)
            if previous_value is not None and previous_value == value:
                return
        if conn is None:
            conn = self.conn
        METRICS[field].set(value, conn)
        self.send_metrics()

    def observe(self, field, value, conn = None):
        if conn is None:
            conn = self.conn
        METRICS[field].observe(value, conn)
        self.send_metrics()

    def serialize_local_metrics(self):
        data = self.load_local_metrics()
        return json.dumps(data)

    def load_local_metrics(self):
        # generate python dictionary of key values from metrics stored in redis
        data = {}
        for field in METRICS:
            data[field] = METRICS[field].decode(self.conn)
        return data

    def store_metrics(self, data_json):
        # called when receiving metrics from other instances
        data = json.loads(data_json)
        logger.debug(f"{self.instance_name} received subsystem metrics from {data['instance']}")
        self.conn.set(root_key + "_instance_" + data['instance'], data['metrics'])

    def send_metrics(self):
        # more than one thread could be calling this at the same time, so should
        # get acquire redis lock before sending metrics
        lock = self.conn.lock(root_key + '_lock', thread_local = False)
        if not lock.acquire(blocking=False):
            return
        try:
            should_broadcast = False
            metrics_last_sent = 0.0
            if not self.conn.exists(root_key + '_last_broadcast'):
                should_broadcast = True
            else:
                last_broadcast = float(self.conn.get(root_key + '_last_broadcast'))
                metrics_last_sent = time.time() - last_broadcast
                if metrics_last_sent > send_metrics_interval:
                    should_broadcast = True
            if should_broadcast:
                payload = {
                    'instance': self.instance_name,
                    'metrics': self.serialize_local_metrics(),
                }
                logger.debug(f"{self.instance_name} sending metrics")
                emit_channel_notification("metrics", payload)
                self.conn.set(root_key + '_last_broadcast', time.time())
        finally:
            lock.release()

    def load_other_metrics(self, request):
        # data received from other nodes are stored in their own keys
        # e.g., awx_metrics_instance_awx-1, awx_metrics_instance_awx-2
        # this method looks for keys with "_instance_" in the name and loads the data
        # also filters data based on request query params
        # if additional filtering is added, update metrics_view.md
        instances_filter = request.query_params.getlist("node")
        # get a sorted list of instance names
        instance_names = [self.instance_name]
        for m in self.conn.scan_iter(root_key + '_instance_*'):
            instance_names.append(m.decode('UTF-8').split('_instance_')[1])
        instance_names.sort()
        # load data, including data from the this local instance
        instance_data = {}
        for instance in instance_names:
            if len(instances_filter) == 0 or instance in instances_filter:
                if instance == self.instance_name:
                    instance_metrics = self.load_local_metrics()
                else:
                    instance_metrics = json.loads(self.conn.get(root_key + '_instance_' + instance).decode('UTF-8'))
                instance_data[instance] = instance_metrics
        return instance_data

    def generate_metrics(self, request):
        # takes the api request, filters, and generates prometheus data
        # if additional filtering is added, update metrics_view.md
        instance_data = self.load_other_metrics(request)
        metrics_filter = request.query_params.getlist("metric")
        output_text = ''
        if instance_data:
            for field in METRICS:
                if len(metrics_filter) == 0 or field in metrics_filter:
                    output_text += METRICS[field].to_prometheus(instance_data)
        return output_text


def metrics(request):
    m = Metrics()
    return m.generate_metrics(request)


# metric name, help_text
METRICSLIST = [
    IntM('callback_receiver_events_queue_size_redis',
         'Current number of events in redis queue'),
    IntM('callback_receiver_events_popped_redis',
         'Number of events popped from redis'),
    IntM('callback_receiver_events_in_memory',
         'Current number of events in memory (in transfer from redis to db)'),
    IntM('callback_receiver_batch_events_errors',
         'Number of times batch insertion failed'),
    FloatM('callback_receiver_events_insert_db_seconds',
           'Time spent saving events to database'),
    IntM('callback_receiver_events_insert_db',
         'Number of events batch inserted into database'),
    HistogramM('callback_receiver_batch_events_insert_db',
               'Number of events batch inserted into database',
               [50, 250, 500, 750, 1000]),
    IntM('callback_receiver_events_insert_redis',
         'Number of events inserted into redis'),
]
# turn metric list into dictionary with the metric name as a key
METRICS = {}
for m in METRICSLIST:
    METRICS[m.field] = m
