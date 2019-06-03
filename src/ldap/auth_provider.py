"""
ldap/auth_provider.py

written by: Oliver Cordes 2019-06-03
changed by: Oliver Cordes 2019-06-03

"""


"""
base class for authentication providers

"""

from passlib.apache import HtpasswdFile    # htpasswd
import pam                                 # PAM

import crypt, pwd
from hmac import compare_digest as compare_hash
import re




class auth_provider(object):
    def __init__(self):
        pass


    def authenticate(self, credentials):
        """
        not implemented
        """
        return False


"""
yes_auth_provider

authenticate all users without checking

"""

class yes_auth_provider(auth_provider):
    def authenticate(self, credentials):
        return True


class realm_auth_provider(auth_provider):
    def __init__(self, realm=None):
        auth_provider.__init__(self)

        self._realm = realm
        if realm is None:
            self._realm = None
        else:
            self._realm = re.compile(r'((uid)|(cn))=(?P<word>[a-zA-Z]+),'+realm)


    def get_real_username(self, name):
        if self._realm is None:
            return name

        m = self._realm.search(name)

        if m is None:
            return name
        else:
            return m.group('word')


"""
test_auth_provider

takes a simple string as username:password combination, comma seperated

"""

class test_auth_provider(realm_auth_provider):
    def __init__(self, credentials, realm=None):
        realm_auth_provider.__init__(self,realm=realm)

        self._data = {}
        c = credentials.replace(' ', '')
        l = credentials.split(',')
        for i in l:
            s = i.split(':')
            self._data.update([s])


    def authenticate(self, credentials):
        username = credentials['user']
        password = credentials['password']

        username = self.get_real_username(username)

        if username in self._data:
            return password == self._data[username]
        else:
            return False


"""
htpasswd_auth_provider

checks the credentials against a given htpasswd file. The realm
is necessary to extract the username from a LDAP People element!

"""
class htpasswd_auth_provider(realm_auth_provider):
    def __init__(self, filename, realm=None):
        realm_auth_provider.__init__(self,realm=realm)

        self._data = HtpasswdFile(filename)


    def authenticate(self, credentials):
        username = credentials['user']
        password = credentials['password']

        username = self.get_real_username(username)

        result = self._data.check_password(username, password)
        if result is None:
            # username is not in database
            return False
        else:
            return result


"""
unix_auth_provider

is a simple authentication provider for unix accounts which have
the passwords inside the passwd file ..., I guess this is more or
less obsolete
"""
class unix_auth_provider(realm_auth_provider):
    def authenticate(self, credentials):
        username = credentials['user']
        password = credentials['password']

        username = self.get_real_username(username)

        try:
            cryptedpasswd = pwd.getpwnam(username)[1]
        except:
            return False

        if cryptedpasswd:
            if cryptedpasswd == 'x' or cryptedpasswd == '*':
                return False
            return compare_hash(crypt.crypt(password, cryptedpasswd), cryptedpasswd)
        else:
            return False



"""
pam_auth_provider

is a simple authentication provider for unix accounts via PAM
"""
class pam_auth_provider(realm_auth_provider):
    def __init__(self, realm=None, service='login'):
        realm_auth_provider.__init__(self, realm=realm)

        self._pam = pam.pam()
        self._service = service


    def authenticate(self, credentials):
        username = credentials['user']
        password = credentials['password']

        username = self.get_real_username(username)

        return self._pam.authenticate(username, password, self._service)
