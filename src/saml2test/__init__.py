import logging
import time
import traceback
import requests
import sys

from subprocess import Popen, PIPE
from saml2test.check import CRITICAL

logger = logging.getLogger(__name__)

__author__ = 'rolandh'


class FatalError(Exception):
    pass


class CheckError(Exception):
    pass


class HTTP_ERROR(Exception):
    pass


class Unknown(Exception):
    pass


# class Trace(object):
#     def __init__(self):
#         self.trace = []
#         self.start = time.time()
#
#     def request(self, msg):
#         delta = time.time() - self.start
#         self.trace.append("%f --> %s" % (delta, msg))
#
#     def reply(self, msg):
#         delta = time.time() - self.start
#         self.trace.append("%f <-- %s" % (delta, msg))
#
#     def info(self, msg, who="saml2client"):
#         delta = time.time() - self.start
#         self.trace.append("%f - INFO - [%s] %s" % (delta, who, msg))
#
#     def error(self, msg, who="saml2client"):
#         delta = time.time() - self.start
#         self.trace.append("%f - ERROR - [%s] %s" % (delta, who, msg))
#
#     def warning(self, msg, who="saml2client"):
#         delta = time.time() - self.start
#         self.trace.append("%f - WARNING - [%s] %s" % (delta, who, msg))
#
#     def __str__(self):
#         return "\n". join([t.encode("utf-8") for t in self.trace])
#
#     def clear(self):
#         self.trace = []
#
#     def __getitem__(self, item):
#         return self.trace[item]
#
#     def next(self):
#         for line in self.trace:
#             yield line


class ContextFilter(logging.Filter):
    """
    This is a filter which injects time laps information into the log.
    """

    def start(self):
        self.start = time.time()

    def filter(self, record):
        record.delta = time.time() - self.start
        return True


def start_script(path, *args):
    popen_args = [path]
    popen_args.extend(args)
    return Popen(popen_args, stdout=PIPE, stderr=PIPE)


def stop_script_by_name(name):
    import subprocess
    import signal
    import os

    p = subprocess.Popen(['ps', '-A'], stdout=subprocess.PIPE)
    out, err = p.communicate()

    for line in out.splitlines():
        if name in line:
            pid = int(line.split(None, 1)[0])
            os.kill(pid, signal.SIGKILL)


def stop_script_by_pid(pid):
    import signal
    import os

    os.kill(pid, signal.SIGKILL)


def get_page(url):
    resp = requests.get(url)
    if resp.status_code == 200:
        return resp.text
    else:
        raise HTTP_ERROR(resp.status)


def exception_trace(tag, exc, log=None):
    message = traceback.format_exception(*sys.exc_info())

    try:
        _exc = "Exception: %s" % exc
    except UnicodeEncodeError:
        _exc = "Exception: %s" % exc.message.encode("utf-8", "replace")

    return {"status": CRITICAL, "message": _exc, "content": "".join(message)}
