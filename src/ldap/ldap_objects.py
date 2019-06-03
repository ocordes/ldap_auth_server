"""

ldap/ldap_objects.py

written by: Oliver Cordes 2019-05-28
changed by: Oliver Cordes 2019-05-28

"""

from pyasn1.codec.ber import encoder, decoder

from ldap.protocol import *

from ldap.auth_provider import htpasswd_auth_provider

from pyasn1 import debug


class LDAP_Object(object):
    def __init__(self):
        pass


    def send(self, connection, newdata):
        data = encoder.encode(newdata)
        print('-->', data)
        x, _ = decoder.decode(data, LDAPMessage())
        print(x)
        connection.send(data)


    def run(self, connection, msgid):
        return msgid+1



class LDAP_Result(LDAP_Object):
    def __init__(self, result_code=53):
        LDAP_Object.__init__(self)

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
    def __init__(self):
        LDAP_Result.__init__(self, 53)

    def run(self, connection, msgid):
        bind_response = BindResponse()
        bind_response['resultCode'] = self._resultcode
        bind_response['matchedDN'] = self._dn
        bind_response['diagnosticMessage'] = self._diagmsg
        l = LDAPMessage()
        l['messageID'] = msgid
        l['protocolOp'] = bind_response
        self.send(connection, l)


class LDAP_SearchResultDone(LDAP_Result):
    def __init__(self):
        LDAP_Result.__init__(self, 32)


    def run(self, connection, msgid):
        search_result_done = SearchResultDone()
        search_result_done['resultCode'] = self._resultcode
        search_result_done['matchedDN'] = self._dn
        search_result_done['diagnosticMessage'] = self._diagmsg
        l = LDAPMessage()
        l['messageID'] = msgid
        l['protocolOp'] = search_result_done
        self.send(connection, l)


class LDAP_Server(object):
    def __init__(self, connection, auth_provider):
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
                return 0, None
            else:
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
        bind_response = LDAP_BindResponse()
        bind_response.resultCode(result)
        if msg is not None:
            bind_response.diagMessage(msg)

        bind_response.run(self._connection, self._msgid)
        self._msgid += 1


    def UnbindRequest(self, data):
        # there is no data to unpack
        self._name = None
        self._version = 3
        self._credentials = None
        self._auth_type = 0
        self._mechanism = None
        self._authenticated = False


    def SearchRequest(self, data):
        search_result_done = LDAP_SearchResultDone()
        search_result_done.run(self._connection, self._msgid)
        self._msgid += 1


    def handle_message(self, data):
        #debug.setLogger(debug.Debug('all'))
        try:
            x, _ = decoder.decode(data, LDAPMessage())
        except:
            print('Error while decoding message')
            x = None

        if x is not None:
            op_x = x['protocolOp']
            op = op_x.getName()
            print('LDAPMessage ->', op)
            if op == 'bindRequest':
                self.BindRequest(op_x.getComponent())
            elif op == 'unbindRequest':
                self.UnbindRequest(op_x.getComponent())
            elif op == 'searchRequest':
                self.SearchRequest(op_x.getComponent())



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


            print(data)
            #print('d:', ' '.join([str(i) for i in data]))
            self.handle_message(data)
