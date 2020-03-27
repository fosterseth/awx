from logging.handlers import RotatingFileHandler
import logging
import multiprocessing, threading, logging, sys, traceback
import os

class QueuedHandler(logging.Handler):
    def __init__(self, *args, **kwargs):
        logging.Handler.__init__(self)

        self._handler = RotatingFileHandler(*args, **kwargs)
        # self._handler.setLevel(logging.DEBUG)
        self.queue = multiprocessing.Queue(-1)

        self.t = threading.Thread(target=self.receive)
        self.t.daemon = True
        self.t.start()

    def setFormatter(self, fmt):
        logging.Handler.setFormatter(self, fmt)
        self._handler.setFormatter(fmt)

    def receive(self):
        while True:
            try:
                record = self.queue.get()
                if record is None:
                    break
                self._handler.emit(record)
            except (KeyboardInterrupt, SystemExit):
                raise
            except EOFError:
                break
            except:
                traceback.print_exc(file=sys.stderr)

    def send(self, s):
        self.queue.put_nowait(s)

    def _format_record(self, record):
        # ensure that exc_info and args have been stringified. Removes any
        # chance of unpickleable things inside and possibly reduces message size
        # sent over the pipe
        record.msg = str(os.getppid()) + "_" + str(id(self)) + "_" + record.msg
        if record.args:
            record.msg = record.msg % record.args
            record.args = None
        if record.exc_info:
            dummy = self.format(record)
            record.exc_info = None

        return record

    def emit(self, record):
        try:
            s = self._format_record(record)
            self.send(s)
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)

    def close(self):
        self.send(None)
        self.t.join() # wait for queue to empty before closing
        self._handler.close()
        logging.Handler.close(self)


class PIDHandler(logging.Handler):
    def __init__(self, *args, **kwargs):
        logging.Handler.__init__(self)

        self.init_kwargs = kwargs
        self.basefilename = self.init_kwargs.pop('filename')

        self._handlers = {}

    def setFormatter(self, fmt):
        logging.Handler.setFormatter(self, fmt)
        for h in self._handlers.values():
            h.setFormatter(fmt)

    def _format_record(self, record):
        # ensure that exc_info and args have been stringified. Removes any
        # chance of unpickleable things inside and possibly reduces message size
        # sent over the pipe
        record.msg = str(os.getppid()) + "_" + str(id(self)) + "_" + record.msg
        if record.args:
            record.msg = record.msg % record.args
            record.args = None
        if record.exc_info:
            dummy = self.format(record)
            record.exc_info = None

        return record

    def emit(self, record):
        try:
            s = self._format_record(record)
            if not self._handlers.get(os.getpid(), None):
                self._handlers[os.getpid()] = RotatingFileHandler(self.basefilename + "_" + str(os.getpid()), **self.init_kwargs)
            self._handlers[os.getpid()].emit(s)
        except (KeyboardInterrupt, SystemExit):
            raise
        except:
            self.handleError(record)

    def close(self):
        for h in self._handlers:
            h.close()
        logging.Handler.close(self)


if __name__ == "__main__":
    logger = logging.getLogger('mylogger')
    handler = QueuedHandler(filename='mylogger.log', maxBytes=5000, backupCount = 5)
    logger.addHandler(handler)

    def write_to_log(threadID):
        for _ in range(1000):
            # time.sleep(50/1000)
            logger.warning(str(threadID) + " Hello, world!")

    workers = []
    for i in range(2):
        p = multiprocessing.Process(target=write_to_log, args=(i,))
        workers.append(p)

    for w in workers:
        w.start()

    for w in workers:
        w.join()
