"""
ldap/auth_provider.py

written by: Oliver Cordes 2019-06-03
changed by: Oliver Cordes 2019-06-04

"""


"""
base class for authentication providers

"""

from passlib.apache import HtpasswdFile    # htpasswd
import pam                                 # PAM
import kerberos                            # kerberos5

import crypt, pwd
from hmac import compare_digest as compare_hash
import re
import subprocess




class auth_provider(object):
    def __init__(self):
        pass


    def authenticate(self, credentials):
        """
        not implemented
        """
        return False


"""
realm_auth_provider

basic class to split a LDAP username into some real
usernam + real
"""
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
gss_realm_auth_provider

provides a seperation of the username into a real username and a realm
"""
class gss_realm_auth_provider(auth_provider):
    def __init__(self):
        auth_provider.__init__(self)

        self._re = re.compile(r'((uid)|(cn))=(?P<user>[a-zA-Z]+),(?P<realm>.+)')


    def get_real_username(self, name):
        m = self._re.search(name)

        if m is None:
            username = name
            realm = ''
        else:
            username = m.group('user')
            realm = m.group('realm')

        return username, realm


"""
yes_auth_provider

authenticate all users without checking

"""

class yes_auth_provider(auth_provider):
    def authenticate(self, credentials):
        return True



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


"""
sasl_auth_provider

is a simple authentication provider which uses sasl to authenticate
"""
class sasl_auth_provider(gss_realm_auth_provider):
    def __init__(self, binary, service='ldap'):
        gss_realm_auth_provider.__init__(self)

        self._binary = binary


    def call_saslauthd(self, user, password):
        username, realm = self.get_real_username(user)

        print(username)
        print(realm)


        cmd = '{} -r {} -u {} -p {}'.format(self._binary, realm, username, password)

        p = subprocess.Popen(cmd, shell=True, bufsize=-1, close_fds=True,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)

        line = p.stdout.readline().decode('utf-8')

        rex = re.compile(r'0: (?P<result>[A-Z]+) "(?P<msg>.+)"')
        m = rex.search(line)
        if m is None:
            return None, None
        return m['result'], m['msg']


    def authenticate(self, credentials):
        username = credentials['user']
        password = credentials['password']

        result, msg = self.call_saslauthd(username, password)

        return result == 'OK'


"""
krb5_auth_provider

is a simple authentication provider which uses krb5 to authenticate,
WARNING: the authentication mechanism works as follows, the library
         tries to get a TGT from the KDC with the username and password via
         kinit ! Nothing more is done! The library warns about KDC spoofing!
"""
class krb5_auth_provider(gss_realm_auth_provider):
    def __init__(self, service=None):
        gss_realm_auth_provider.__init__(self)



    def authenticate(self, credentials):
        username = credentials['user']
        password = credentials['password']


        username, realm = self.get_real_username(username)

        try:
            if service is None:
                service = 'ldap'
            return kerberos.checkPassword(username, password, service, realm)
        except kerberos.BasicAuthError as e:
            print(e)
            return False
        except:
            print('Other Error')
            return False
