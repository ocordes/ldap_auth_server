"""

ldap/whitelists.py

written by: Oliver Cordes 2019-06-04
changed by: Oliver Cordes 2019-09-10

"""

import os, sys


class WhiteLists(object):
    def __init__(self, lists, logger=None):
        self._logger = logger

        self._whitelist = {}

        if lists is None:
            self._whitelist = None
        else:
            self._whitelist = {}
            for i in lists.split(','):
                self._whitelist[i] = [ 0, []]

                self._updatelists()



    def _readlist(self, filename, timestamp):
        mtime = os.path.getmtime(filename)
        if mtime > timestamp:
            # read the file again
            if self._logger is not None:
                self._logger.write('Reread whitelist: {}'.format(filename))
            with open(filename) as f:
                lines = f.read().splitlines()

            nlines = []
            for i in lines:
              line = i.strip()
              if len(line) > 0:   # check if line if zero
                if line[0] != '#':
                   nlines.append(line)

            return mtime, nlines
        else:
            return None, None


    def _updatelists(self):
        if self._whitelist is None: return
        for i in self._whitelist:
            mtime, data = self._readlist(i, self._whitelist[i][0])
            if mtime is not None:
                self._whitelist[i][0] = mtime
                self._whitelist[i][1] = data


    def whitelisted(self, username):
        if self._whitelist is None:
            # no whitelist exists accept everybody
            return True

        self._updatelists()

        for i in self._whitelist:
            if username in self._whitelist[i][1]:
                if self._logger is not None:
                    self._logger.write('User: {} accepted by whitelist'.format(username))
                return True

        return False


    def get_userlist(self):
        self._updatelists()
        users = []
        if self._whitelist is not None:
           for i in self._whitelist:
              userlist = [u for u in self._whitelist[i][1]]
              users += userlist
        return users
