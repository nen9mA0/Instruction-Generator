import logging
import sys

class logger_t(object):
    # stream_loglevel = (logging.ERROR, )
    stream_loglevel = (logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR)
    # file_loglevel = (logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR)
    file_loglevel = (logging.ERROR, )

    def __init__(self, filename="", stream_loglevel=None, file_loglevel=None):
        if stream_loglevel != None:
            self.stream_loglevel = stream_loglevel
        if file_loglevel != None:
            self.file_loglevel = file_loglevel

        self.log = logging.getLogger()
        self.log.setLevel(logging.DEBUG)

        self.streamlog = logging.StreamHandler(sys.stderr)
        stream_filter = logging.Filter()
        stream_filter.filter = lambda record: record.levelno in self.stream_loglevel
        self.streamlog.addFilter(stream_filter)

        self.log.addHandler(self.streamlog)

        if filename != "":
            self.filelog = logging.FileHandler(filename, "w")
            filefitler = logging.Filter()
            filefitler.filter = lambda record: record.levelno in self.file_loglevel
            self.filelog.addFilter(filefitler)

            self.log.addHandler(self.filelog)

    def debug(self, msg):
        return self.log.debug(msg)

    def info(self, msg):
        return self.log.info(msg)

    def warning(self, msg):
        return self.log.warning(msg)

    def error(self, msg):
        return self.log.error(msg)
