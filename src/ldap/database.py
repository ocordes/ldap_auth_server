"""
ldap/database.py

written by: Oliver Cordes 2019-06-12
changed by: Oliver Cordes 2019-06-12

"""
import re
import copy


fake_database_entry = {'objectClass': ['posixAccount', 'inetOrgPerson', 'person'],
                        'cn' : '<username>',
                        'sn' : '<username>',
                        'uid' : '<username>' }


class Database(object):
    def __init__(self, logger=None):
        self._logger = logger

        if self._logger is not None:
            self._logger.write('Using a fake database...')


    def modify_string(self, s, username):
        return s.replace('<username>', username)


    def create_fake_database_entry(self, template, username, realm):
        result = {}

        for k in template.keys():
            if isinstance(template[k], (list, tuple)):
                newl = [self.modify_string(i, username) for i in template[k]]
                result[k] = newl
            else:
                result[k] = self.modify_string(template[k], username)


        return result



    def split_username(self, username):
        rex = re.compile(r'((uid)|(cn))=(?P<user>[a-zA-Z]+),(?P<realm>.+)')

        m = rex.search(username)

        if m is None:
            realm = ''
        else:
            username = m.group('user')
            realm = m.group('realm')

        return username, realm


    def search_database(self, searchobj, username):
        username, realm = self.split_username(username)
        if self._logger is not None:
            self._logger.write('database: username={} realm={}'.format(username, realm))


        result = {}

        databasename = 'uid={},{}'.format(username, realm)
        result[databasename] = self.create_fake_database_entry(fake_database_entry, username, realm)

        self._logger.write(result)

        return result
