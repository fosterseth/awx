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
        self.current_value = 0

    def inc(self, value):
        self.current_value += value

    def set(self, value):
        self.current_value = value

    def decode(self, conn):
        value = conn.hget(root_key, self.field)
        return self.decode_value(value)

    def to_prometheus(self, instance_data):
        output_text = f"# HELP {self.field} {self.help_text}\n# TYPE {self.field} gauge\n"
        for instance in instance_data:
            output_text += f'{self.field}{{node="{instance}"}} {instance_data[instance][self.field]}\n'
        return output_text


class FloatM(BaseM):
    def decode_value(self, value):
        if value is not None:
            return float(value)
        else:
            return 0.0

    def store_value(self, conn):
        conn.hincrbyfloat(root_key, self.field, self.current_value)
        self.current_value = 0


class IntM(BaseM):
    def decode_value(self, value):
        if value is not None:
            return int(value)
        else:
            return 0

    def store_value(self, conn):
        conn.hincrby(root_key, self.field, self.current_value)
        self.current_value = 0


class SetM(BaseM):
    def decode_value(self, value):
        if value is not None:
            return int(value)
        else:
            return 0

    def store_value(self, conn):
        # do not set value if it has not changed since last time this was called
        if self.current_value is not None:
            conn.hset(root_key, self.field, self.current_value)
            self.current_value = None


class HistogramM(BaseM):
    def __init__(self, field, help_text, buckets):
        self.buckets = buckets
        self.buckets_to_keys = {}
        for b in buckets:
            self.buckets_to_keys[b] = IntM(field + '_' + str(b), '')
        self.inf = IntM(field + '_inf', '')
        self.sum = IntM(field + '_sum', '')
        super(HistogramM, self).__init__(field, help_text)

    def observe(self, value):
        for b in self.buckets:
            if value <= b:
                self.buckets_to_keys[b].inc(1)
                break
        self.sum.inc(value)
        self.inf.inc(1)

    def decode(self, conn):
        values = {'counts':[]}
        for b in self.buckets_to_keys:
            values['counts'].append(self.buckets_to_keys[b].decode(conn))
        values['sum'] = self.sum.decode(conn)
        values['inf'] = self.inf.decode(conn)
        return values

    def store_value(self, conn):
        for b in self.buckets:
            self.buckets_to_keys[b].store_value(conn)
        self.sum.store_value(conn)
        self.inf.store_value(conn)

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
    def __init__(self, auto_pipe_execute = True, pipe_execute_interval = 2):
        self.pipe = redis.Redis.from_url(settings.BROKER_URL).pipeline()
        self.conn = redis.Redis.from_url(settings.BROKER_URL)
        self.last_pipe_execute= time.time()
        self.pipe_execute_interval = pipe_execute_interval
        # auto pipe execute will commit transaction of metric data to redis
        # at a regular interval (pipe_execute_interval). If set to False,
        # the calling function should call .pipe_execute() explicitly
        self.auto_pipe_execute = auto_pipe_execute
        Instance = apps.get_model('main', 'Instance')
        instance_name = Instance.objects.me().hostname
        self.instance_name = instance_name

        # metric name, help_text
        METRICSLIST = [
            SetM('callback_receiver_events_queue_size_redis',
                 'Current number of events in redis queue'),
            IntM('callback_receiver_events_inserted_redis',
                 'Number of playbook events inserted into redis'),
            IntM('callback_receiver_events_popped_redis',
                 'Number of events popped from redis'),
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
                       settings.SUBSYSTEM_METRICS_BATCH_INSERT_BUCKETS),
        ]
        # turn metric list into dictionary with the metric name as a key
        self.METRICS = {}
        for m in METRICSLIST:
            self.METRICS[m.field] = m

    def inc(self, field, value):
        if value != 0:
            self.METRICS[field].inc(value)
            if self.auto_pipe_execute is True and self.should_pipe_execute() is True:
                self.pipe_execute()

    def set(self, field, value):
        self.METRICS[field].set(value)
        if self.auto_pipe_execute is True and self.should_pipe_execute() is True:
            self.pipe_execute()

    def observe(self, field, value):
        self.METRICS[field].observe(value)
        if self.auto_pipe_execute is True and self.should_pipe_execute() is True:
            self.pipe_execute()

    def serialize_local_metrics(self):
        data = self.load_local_metrics()
        return json.dumps(data)

    def load_local_metrics(self):
        # generate python dictionary of key values from metrics stored in redis
        data = {}
        for field in self.METRICS:
            data[field] = self.METRICS[field].decode(self.conn)
        return data

    def store_metrics(self, data_json):
        # called when receiving metrics from other instances
        data = json.loads(data_json)
        logger.debug(f"{self.instance_name} received subsystem metrics from {data['instance']}")
        self.conn.set(root_key + "_instance_" + data['instance'], data['metrics'])

    def should_pipe_execute(self):
        if time.time() - self.last_pipe_execute > self.pipe_execute_interval:
            return True
        else:
            return False

    def pipe_execute(self, pipe=None):
        passed_in_pipe = False
        if pipe:
            passed_in_pipe = True
        else:
            pipe = self.pipe
        for m in self.METRICS:
            self.METRICS[m].store_value(pipe)
        res = pipe.execute()
        if not passed_in_pipe:
            self.last_pipe_execute = time.time()
        return res

    def send_metrics(self):
        payload = {
            'instance': self.instance_name,
            'metrics': self.serialize_local_metrics(),
        }
        # store a local copy as well
        self.store_metrics(json.dumps(payload))
        emit_channel_notification("metrics", payload)

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
                instance_data_from_redis = self.conn.get(root_key + '_instance_' + instance)
                '''
                Data from other instances may not be available. That is OK.
                '''
                if instance_data_from_redis:
                    instance_data[instance] = json.loads(instance_data_from_redis.decode('UTF-8'))
        return instance_data

    def generate_metrics(self, request):
        # takes the api request, filters, and generates prometheus data
        # if additional filtering is added, update metrics_view.md
        instance_data = self.load_other_metrics(request)
        metrics_filter = request.query_params.getlist("metric")
        output_text = ''
        if instance_data:
            for field in self.METRICS:
                if len(metrics_filter) == 0 or field in metrics_filter:
                    output_text += self.METRICS[field].to_prometheus(instance_data)
        return output_text


def metrics(request):
    m = Metrics()
    return m.generate_metrics(request)
