"""

ldap/logger.py

written by: Oliver Cordes 2019-06-04
changed by: Oliver Cordes 2019-06-04

"""

import sys
import datetime

LOGGER_STDOUT = 0
LOGGER_STDERR = 1
LOGGER_FILE   = 2

class logger(object):
    def __init__(self, logtype, logfilename='logger.log'):

        self._logfile = None

        if logtype == LOGGER_FILE:
            try:
                self._logfile = open(logfilename, 'w')
            except:
                self._logfile = sys.stderr
        elif logtype == LOGGER_STDOUT:
            self._logfile = sys.stdout
        else:
            self._logfile = sys.stderr

        self.write('Logging started...')


    def __del__(self):
        if self._logfile not in (sys.stdout, sys.stderr):
            self._logfile.close()


    def write(self, *vars):
        dt = datetime.datetime.now()
        s = ' '.join([str(i) for i in vars])
        print('{}: {}'.format(dt.strftime('%F %T'), s),
                 file=self._logfile, flush=True)
