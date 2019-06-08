"""
ldap/rfc4511.py

written by: Oliver Cordes 2019-06-08
changed by: Oliver Cordes 2019-06-08

"""

from asn1_tags import Tag, tagClassUniversal, tagClassApplication, \
                            tagClassContext, tagClassPrivate, \
                            tagFormatSimple, tagFormatConstructed
from asn1_types import *


class LDAPString(OctetString):
    pass


class LDAPDN(OctetString):
    pass


class AttributeDescription(LDAPString):
    pass


class BindRequest(Sequence):
    pass


class BaseObject(LDAPDN):
    pass


class Scope(Enumerated):
    valuemap = ValueMap(('baseObject', 0),
                        ('singleLevel', 1),
                        ('wholeSubtree', 2))


class DerefAliases(Enumerated):
    namedValues = NamedValues(
                    NamedType('neverDerefAliases', 0),
                    NamedType('derefInSearching', 1),
                    NamedType('derefFindingBaseObj', 2),
                    NamedType('derefAlways', 3)
    )


class SizeLimit(Integer):
    pass


class TimeLimit(Integer):
    pass


class TypesOnly(Boolean):
    pass


class Filter(Choice):
    pass


class AndFilter(Set):
    tag = Tag(tagClassContext, tagFormatConstructed, 0)




class PresentFilter(AttributeDescription):
    
    pass


Filter.namedValues = NamedValues(
    NamedType('and', AndFilter()),
    NamedType('present', PresentFilter()),
)

class SearchRequest(Sequence):
    tag = Tag(tagClassApplication, tagFormatConstructed, 3)
    namedValues = NamedValues(
        NamedType('baseObject', BaseObject()),
        NamedType('scope', Scope()),
        NamedType('derefAliases', DerefAliases()),
        NamedType('sizeLimit', SizeLimit()),
        NamedType('timeLimit', TimeLimit()),
        NamedType('typesOnly', TypesOnly()),
        NamedType('filter', Filter()),
    )


class MessageID(Integer):
    pass


class ProtocolOp(Choice):
    namedValues = NamedValues(
        NamedType('bindRequest', BindRequest()),
        NamedType('searchRequest', SearchRequest()),
    )



class LDAPMessage(Sequence):
    namedValues = NamedValues(
        NamedType('messageID', MessageID()),
        NamedType('protocolOp', ProtocolOp()),
    )
