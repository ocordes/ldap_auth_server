"""

ldap/asn1_coding.py

writtem by: Oliver Cordes 2019-06-08
changed by: Oliver Cordes 2019-06-10

"""

"""
all based on this arcticle:

https://en.wikipedia.org/wiki/X.690
"""

from asn1_types import asn1base


"""
decode

is the main decoding function
"""
def decode(substrate, schema=None):
    obj, substrate = asn1base.decode(substrate, schema=schema)

    return obj, substrate

"""
encode

is the main encoding function
"""

def encode(obj):
    return obj.encode()
