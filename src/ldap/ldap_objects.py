"""

ldap/ldap_objects.py

written by: Oliver Cordes 2019-05-28
changed by: Oliver Cordes 2019-05-28

"""

from pyasn1.codec.ber import encoder, decoder

from ldap.protocol import *


class LDAP_Object(object):
    def __init__(self, asn1type=None):
        self._asn1type = asn1type


    def send(self, connection):
        pass


"""
decode_message
"""
def decode_message(msg_data):
    try:
        x, _ = decoder.decode(data, LDAPMessage())
    except:
        x = None

    return x
