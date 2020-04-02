"""
ldap/database.py

written by: Oliver Cordes 2019-06-12
changed by: Oliver Cordes 2020-03-26

"""
import re
import copy
import uuid


groupid = '100'

fake_database_entry = {'objectclass': ['posixaccount', 'inetorgperson', 'person'],
                        'gidnumber': groupid,
                        'cn' : '<username>',
                        'sn' : '<username>',
                        'uid' : '<username>',
                        'displayname' : '<username>',
                        'memberof' : 'cn=users,ou=group,dc=UNI-BONN,dc=DE',
                        'quota' : 'none',
                        'userpassword' : 'hallo',
                        'mail' : '<username>@uni-bonn.de' }
fake_database_1     = {'objectclass': ['posixaccount', 'inetorgperson', 'person'],
                        'gidnumber': groupid,
                        'cn' : 'Hugo',
                        'sn' : 'Hugo',
                        'uid' : 'Hugo',
                        'displayname' : 'Hugo von Borst',
                        'memberof' : 'cn=users,ou=group,dc=uni-bonn,dc=de',
                        'quota' : 'none',
                        'userpassword' : 'hallo',
                        'mail' : 'hugo@mail.mail' }

fake_database_group = {'objectclass': ['posixgroup'],
                        'description': 'Users',
                        'gidnumber': groupid,
                        'memberUid' : 'ocordes',
                        'displayname' : 'Users',
                        'cn': 'users' }


class Database(object):
    def __init__(self, userlist, realm, logger=None):
        self._logger = logger

        if self._logger is not None:
            self._logger.write('Using a fake database...')
            self._logger.write('Creating entries for {} users...'.format(len(userlist)))

        # create the complete database
        self._db = {}
        self._realm = realm
        for username in userlist:
           dbname = 'uid={},{}'.format(username, realm).lower()
           self._db[dbname] = self.create_fake_database_entry(fake_database_entry, username, realm)
        dbname = 'uid={},{}'.format('hugo', realm).lower()
        self._db[dbname] = fake_database_1

        # add a group
        dbname = 'cn=users,ou=group,{}'.format(realm).lower()
        self._db[dbname] = fake_database_group

        print(self._db)


    def modify_string(self, s, username):
        if isinstance(s, str):
            return s.replace('<username>', username)
        else:
            return s


    def create_fake_database_entry(self, template, username, realm):
        result = {}

        for k in template.keys():
            kl = k.lower()
            if isinstance(template[k], (list, tuple)):
                newl = [self.modify_string(i, username).lower() for i in template[k]]
                result[kl] = newl
            else:
                result[kl] = self.modify_string(template[k], username).lower()


        result['entryuuid'] = str(uuid.uuid5(uuid.NAMESPACE_DNS, username))

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

    """
    search_database_simple

    is a simple search for all entries in the database
    """
    def search_database_simple(self, searchobj, username):
        username, realm = self.split_username(username)
        if self._logger is not None:
            self._logger.write('database: username={} realm={}'.format(username, realm))

        # check if realm is identical to the baseObject

        if searchobj['baseObject'] == realm:
            self._logger.write('database: searching the complete database')
            result = self._db
        else:
            self._logger.write('database: return the info of the login user only')

            databasename = 'uid={},{}'.format(username, realm)
            result = self._db[databasename]

        return result


    """
    _filter_present

    returns all entries of db which have the attribute attribute
    """
    def _filter_present(self, db, attribute):
        if self._logger is not None:
            self._logger.write('search: attribute={} present'.format(attribute))
        return {i:db[i] for i in db if attribute in db[i]}


    """
    _filter_equal

    returns all entries of db which have a value for atttribute attribute of value
    """
    def _filter_equal(self, db, attribute, value):
        if self._logger is not None:
            self._logger.write('search: attribute="{} == {}"'.format(attribute, value))
        newdb = {}
        for i in db:
            match = False
            if attribute in db[i]:
                if isinstance(db[i][attribute], (tuple, list)):
                    match = value in db[i][attribute]
                else:
                    match = db[i][attribute] == value
            if match:
                newdb[i] = db[i]

        return newdb

        #return {i:db[i] for i in db if (attribute in db[i]) and (db[i][attribute] == value) }


    """
    _filter_greaterorequal

    returns all entries of db which have a value for atttribute attribute >= value
    """
    def _filter_greaterorequal(self, db, attribute, value):
        if self._logger is not None:
            self._logger.write('search: attribute="{} >= {}"'.format(attribute, value))
        return {i:db[i] for i in db if (attribute in db[i]) and (db[i][attribute] >= value) }


    """
    _filter_lessorequal

    returns all entries of db which have a value for atttribute attribute <= value
    """
    def _filter_lessorequal(self, db, attribute, value):
        if self._logger is not None:
            self._logger.write('search: attribute="{} <= {}"'.format(attribute, value))
        return {i:db[i] for i in db if (attribute in db[i]) and (db[i][attribute] <= value) }


    """
    _filter_and

    returns all entries of db which fits into "all" subfilters
    """
    def _filter_and(self, db, filter_list):
        if self._logger is not None:
            self._logger.write('search: and with {} components'.format(len(filter_list)))

        # apply the and filter to the list
        # it reduces the list in each step, which is a natural 'and'
        for filter in filter_list:
            db = self.filter_db(db, filter, '')

        if self._logger is not None:
            self._logger.write('search: and complete')
        return db


    """
    _merge_or

    returns a merged list which no duplicates
    """
    def _merge_or(self, db1, db2):
        db = copy.copy(db1)

        for el in db2:
            if el not in db1:
                db[el] = db2[el]

        return db

    """
    _filter_or

    returns all entries of db which fits into "any" subfilters
    """
    def _filter_or(self, db, filter_list):
        if self._logger is not None:
            self._logger.write('search: or with {} components'.format(len(filter_list)))

        # apply the and filter to the list
        # it reduces the list in each step, which is a natural 'and'
        rdb = {}
        for filter in filter_list:
            ndb = self.filter_db(db, filter, '')
            rdb = self._merge_or(rdb, ndb)

        if self._logger is not None:
            self._logger.write('search: or complete')
        return rdb


    """2
    """
    def _filter_not(self, db, nfilter):
        ndb = self.filter_db(db, nfilter, '')

        return {i:db[i] for i in db if i not in ndb}


    """
    filter_db

    is a search routine in the database, it can be used recursively
    """
    def filter_db(self, db, filter, username):
        filter_name = filter.getName()

        if filter_name == 'present':
            attribute = filter[filter_name].lower()
            db = self._filter_present(db, attribute)
        elif filter_name == 'equalityMatch':
            attribute = filter[filter_name]['attributeDesc'].lower()
            value = filter[filter_name]['assertionValue'].lower()
            db = self._filter_equal(db, attribute, value)
        elif filter_name == 'greaterOrEqual':
            attribute = filter[filter_name]['attributeDesc'].lower()
            value = filter[filter_name]['assertionValue'].lower()
            db = self._filter_greaterorequal(db, attribute, value)
        elif filter_name == 'lessOrEqual':
            attribute = filter[filter_name]['attributeDesc'].lower()
            value = filter[filter_name]['assertionValue'].lower()
            db = self._filter_lessorequal(db, attribute, value)
        elif filter_name == 'and':
            db = self._filter_and(db, filter[filter_name])
        elif filter_name == 'or':
            db = self._filter_or(db, filter[filter_name])
        elif filter_name == 'notFilter':
            db = self._filter_not(db, filter[filter_name]['filter'])
        else:
            if self._logger is not None:
                self._logger.write('search not implemented ({}); return all entries!'.format(filter_name))

        if self._logger is not None:
            self._logger.write('Search result: {} entries'.format(len(db)))

        return db

    """
    search_database

    is the tool which filters the whole "fake database"
    """
    def search_database(self, searchobj, username):

        return self.filter_db(self._db, searchobj['filter'], username)
