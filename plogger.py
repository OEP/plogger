import re
from datetime import datetime

class ParseError(Exception):
  pass

class SyslogEntry(object):
  def __init__(self, timestamp, tag, host=None, pid=None, message=None):
    self.timestamp = timestamp
    self.tag = tag
    self.host = host
    self.pid = pid
    self.message = message

  def __str__(self):
    timestamp = self.timestamp.strftime(syslog_timefmt)
    fmt = "{timestamp} {host} {tag}: {message}"
    if not self.pid is None:
      fmt = "{timestamp} {host} {tag}[{pid}]: {message}"
    return fmt.format(
      timestamp=timestamp, host=self.host or '', tag=self.tag, pid=self.pid,
      message=self.message or '',
    )

  def __repr__(self):
    return "<%s: %s>" % (type(self).__name__, self)

class LogParser(object):

  def parse(self, fp):
    raise NotImplementedError()

syslog_timefmt = '%b %d %H:%M:%S'
syslog_rx = (r'(?P<timestamp>[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d) '
             + r'(?P<host>[^ ]+)? '
             + r'(?P<tag>[^[]+)'
             + r'([[](?P<pid>\d+)[]])?: '
             + r'(?P<message>.+)?')
syslog_rx = re.compile(syslog_rx)
class SyslogParser(LogParser):
  def parse(self, fp):
    lineno = 0
    result = []
    for line in fp:
      lineno += 1
      m = syslog_rx.match(line)
      if not m:
        raise ParseError(lineno, line)
      timestamp, host, tag, pid, message = m.group(
        'timestamp', 'host', 'tag', 'pid', 'message'
      )
      timestamp = datetime.strptime(timestamp, syslog_timefmt)
      pid = int(pid) if pid is not None else None
      entry = SyslogEntry(timestamp, tag, host, pid, message)
      result.append(entry)
    return result
