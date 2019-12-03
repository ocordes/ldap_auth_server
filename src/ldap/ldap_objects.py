"""

ldap/ldap_objects.py

written by: Oliver Cordes 2019-05-28
changed by: Oliver Cordes 2019-09-10

"""

from ldap.asn1_coding import encode, decode

from ldap.rfc4511 import *
from ldap.asn1_debug import *

from ldap.auth_provider import htpasswd_auth_provider
from ldap.database import Database

from pyasn1 import debug

import traceback


class LDAP_Object(object):
    def __init__(self, logger=None, debug=False):
        self._logger = logger
        self._debug  = debug


    def send(self, connection, newdata):
        data = encode(newdata)
        if (self._logger is not None) and self._debug:
            self._logger.write('-->', data)
            self._logger.write('-->', octed2string(data))
        x, _ = decode(data, LDAPMessage())
        if (self._logger is not None) and self._debug:
            self._logger.write(x)
        connection.send(data)


    def run(self, connection, msgid):
        return msgid+1



class LDAP_Result(LDAP_Object):
    def __init__(self, result_code=53, logger=None, debug=False):
        LDAP_Object.__init__(self, logger=logger, debug=debug)

        # copy the information from the asn1 structure

        self._resultcode = result_code
        self._dn = ''
        self._diagmsg = ''


    def resultCode(self, code):
        self._resultcode = code


    def matchedDN(self, dn):
        self._dn = dn


    def diagMessage(self, msg):
        self._diagmsg = msg




class LDAP_BindResponse(LDAP_Result):
    def __init__(self, logger=None, debug=False):
        LDAP_Result.__init__(self, 53, logger=logger, debug=debug)

    def run(self, connection, msgid):
        bind_response = BindResponse()
        bind_response['resultCode'] = self._resultcode
        bind_response['matchedDN'] = self._dn
        bind_response['diagnosticMessage'] = self._diagmsg
        l = LDAPMessage()
        l['messageID'] = msgid
        l['protocolOp'] = bind_response
        if (self._logger is not None) and self._debug:
            self._logger.write('--> msgID', msgid)
        self.send(connection, l)


class LDAP_SearchResultDone(LDAP_Result):
    def __init__(self, result_code=32, logger=None, debug=False):
        LDAP_Result.__init__(self, result_code, logger=logger, debug=debug)


    def run(self, connection, msgid):
        search_result_done = SearchResultDone()
        search_result_done['resultCode'] = self._resultcode
        search_result_done['matchedDN'] = self._dn
        search_result_done['diagnosticMessage'] = self._diagmsg
        l = LDAPMessage()
        l['messageID'] = msgid
        l['protocolOp'] = search_result_done
        self.send(connection, l)


class LDAP_SearchResultEntry(LDAP_Object):
    def __init__(self, dn, data, logger=None, debug=False):
        LDAP_Object.__init__(self, logger=logger, debug=debug)

        self._dn   = dn
        self._data = data


    def run(self, connection, msgid):
        search_result_entry = SearchResultEntry()
        search_result_entry['object'] = self._dn
        search_result_entry['attributes'] = []

        for key in self._data.keys():
            attr = PartialAttribute()
            attr['type'] = key
            if isinstance(self._data[key], (tuple,list)):
                attr['vals'] = self._data[key]
            else:
                attr['vals'] = [self._data[key]]
            search_result_entry['attributes'].append(attr)

        l = LDAPMessage()
        l['messageID'] = msgid
        l['protocolOp'] = search_result_entry
        self.send(connection, l)


class LDAP_Server(object):
    def __init__(self, connection, auth_provider, database=None, logger=None, debug=False):
        self._logger = logger
        self._debug = debug
        if database is not None:
            self._database = Database(logger=logger)
        else:
            self._database = None
        self._connection = connection
        self._msgid      = 1

        # auth data
        self._authenticated = False
        self._name = None
        self._version = 3
        self._credentials = None
        self._auth_type = 0
        self._mechanism = None

        # authentification provider
        self._auth_provider = auth_provider

        if self._debug:
            debug_on()

    # do the authentification
    def _check_authentication(self):
        if self._credentials == '':
            return 53, 'unauthenticated bind (DN with no password) disallowed'
        else:
            credentials = { 'user' : self._name,
                            'password' : self._credentials,
                            'mechanism': self._mechanism }

            self._authenticated = self._auth_provider.authenticate(credentials)
            if self._authenticated:
                if self._logger is not None:
                    self._logger.write('User: {} is authenticated!'.format(self._name))
                return 0, None
            else:
                if self._logger is not None:
                    self._logger.write('Authentication for user: {} failed!'.format(self._name))
                return 49, 'invalid username/password settings'


    # deal with the LDAP messages

    def BindRequest(self, data):
        # unpack data
        self._version = int(data['version'])
        self._name = str(data['name'])

        if data['authentication'].getName() == 'simple':
            self._auth_type = 0
            self._credentials = str(data['authentication']['simple'])
        else:
            self._auth_type = 1
            x = data['authentication']['sasl']
            self._credentials = str(x['credentials'])
            self._mechanism  = x['mechanism']

        result, msg = self._check_authentication()

        # send the response
        bind_response = LDAP_BindResponse(logger=self._logger, debug=self._debug)
        bind_response.resultCode(result)
        if msg is not None:
            bind_response.diagMessage(msg)

        bind_response.run(self._connection, self._msgid)


    def UnbindRequest(self, data):
        # there is no data to unpack
        self._name = None
        self._version = 3
        self._credentials = None
        self._auth_type = 0
        self._mechanism = None
        self._authenticated = False


    def SearchRequest(self, data):
        success = False
        if self._database is not None:
            results = self._database.search_database(data, self._name, self._auth_provider.get_userlist())
            for key in results.keys():
                if self._debug:
                   self._logger.write('search_result:', key)
                result_entry = LDAP_SearchResultEntry(key, results[key], logger=self._logger, debug=self._debug)
                result_entry.run(self._connection, self._msgid)
                success = True

        if success:
            search_result_done = LDAP_SearchResultDone(result_code=0, logger=self._logger, debug=self._debug)
        else:
            search_result_done = LDAP_SearchResultDone(logger=self._logger, debug=self._debug)
        search_result_done.run(self._connection, self._msgid)


    """
    handle_message

    decodes the incoming LDAPMessage and redicted the decoded payload
    to the subroutines, the msgid is extracted and used for any related
    LDAP response messages!
    """
    def handle_message(self, data):
        #debug.setLogger(debug.Debug('all'))
        try:
            x, _ = decode(data, LDAPMessage())
            if (self._logger is not None) and self._debug:
                self._logger.write(x.prettyPrint())
            self._msgid = x['messageID']
        except:
            if (self._logger is not None) and self._debug:
                self._logger.write('Error while decoding message')
                self._logger.write(traceback.format_exc())
            x = None

        if x is not None:
            op_x = x['protocolOp']
            op = op_x.getName()
            if (self._logger is not None) and self._debug:
                self._logger.write('LDAPMessage ->', op)
            if op == 'bindRequest':
                self.BindRequest(op_x[op])
            elif op == 'unbindRequest':
                self.UnbindRequest(op_x[op])
            elif op == 'searchRequest':
                self.SearchRequest(op_x[op])



    def _receive_from(self):
        buffer = b""

        # we set a 2 second timeout; depending on your
        # target, this may need to be adjusted
        self._connection.settimeout(0.05)

        try:
            # keep reading into the buffer until
            # there's no more data or we timeout
            count = 0
            while True:
                count += 1
                data = self._connection.recv(4096)

                if not data:
                    break

                buffer += data

        except:
            pass

        return buffer


    def run(self):
        self._msgid = 1
        while True:
            # data received from client
            data = self._receive_from()

            if not data:
                break

            if (self._logger is not None) and self._debug:
            #    self._logger.write(data)
            #    self._logger.write('d:', ' '.join([str(i) for i in data]))
               self._logger.write('<--', data)
               self._logger.write('<--', octed2string(data))

            self.handle_message(data)
