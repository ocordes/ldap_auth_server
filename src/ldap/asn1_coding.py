"""

ldap/asn1_coding.py

writtem by: Oliver Cordes 2019-06-08
changed by: Oliver Cordes 2019-06-08

"""

"""
all based on this arcticle:

https://en.wikipedia.org/wiki/X.690
"""

from asn1_tags import Tag, tagClassUniversal, tagClassApplication, \
                            tagClassContext, tagClassPrivate, \
                            tagFormatSimple, tagFormatConstructed


from asn1_types import asn1base


class Decoder(object):
    def __init__(self):
        pass



    """
    decode

    is the main decoding function
    """
    def decode(self, substrate, schema=None):
        obj, substrate = asn1base.decode(substrate, schema=schema)

        return obj, substrate
