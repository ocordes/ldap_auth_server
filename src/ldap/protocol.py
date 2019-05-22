"""

src/ldap/protocol.py

written by: Oliver Cordes 2019-05-22
changed by: Oliver Cordes 2019-05-22
"""


# Imports from pyasn1
from pyasn1.type import tag, namedtype, namedval, univ, constraint
from pyasn1.codec.ber import encoder, decoder


# https://tools.ietf.org/html/rfc4511

class SaslCredentials(univ.Sequence):
    """
    SaslCredentials ::= SEQUENCE {
             mechanism               LDAPString,
             credentials             OCTET STRING OPTIONAL }
    """
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('mechanism', univ.OctetString()),
        namedtype.NamedType('credentials', univ.OctetString()),
    )


class AuthenticationChoice(univ.Choice):
    """
    AuthenticationChoice ::= CHOICE {
             simple                  [0] OCTET STRING,
                                     -- 1 and 2 reserved
             sasl                    [3] SaslCredentials,
             ...  }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('simple', univ.OctetString().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('sasl', SaslCredentials()),
    )


class Version(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(1, 127)


class BindRequest(univ.Sequence):
    """
    BindRequest ::= [APPLICATION 0] SEQUENCE {
             version                 INTEGER (1 ..  127),
             name                    LDAPDN,
             authentication          AuthenticationChoice }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Version()),
        namedtype.NamedType('name', univ.OctetString()),
        #namedtype.NamedType('authentication', univ.Integer()),
        #namedtype.NamedType('authentication', AuthenticationChoice())
        #namedtype.OptionalNamedType('controls', univ.Integer() ),
    )

class SearchRequest(univ.Sequence):
    """
    SearchRequest ::= [APPLICATION 3] SEQUENCE {
             baseObject      LDAPDN,
             scope           ENUMERATED {
                  baseObject              (0),
                  singleLevel             (1),
                  wholeSubtree            (2),
                  ...  },
             derefAliases    ENUMERATED {
                  neverDerefAliases       (0),
                  derefInSearching        (1),
                  derefFindingBaseObj     (2),
                  derefAlways             (3) },
             sizeLimit       INTEGER (0 ..  maxInt),
             timeLimit       INTEGER (0 ..  maxInt),
             typesOnly       BOOLEAN,
             filter          Filter,
             attributes      AttributeSelection }

        AttributeSelection ::= SEQUENCE OF selector LDAPString
                        -- The LDAPString is constrained to
                        -- <attributeSelector> in Section 4.5.1.8

        Filter ::= CHOICE {
             and             [0] SET SIZE (1..MAX) OF filter Filter,
             or              [1] SET SIZE (1..MAX) OF filter Filter,
             not             [2] Filter,

    """
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('baseObject', univ.OctetString()),
    )



class LDAPOp(univ.Choice):
    """
    protocolOp      CHOICE {
         bindRequest           BindRequest,
         bindResponse          BindResponse,
         unbindRequest         UnbindRequest,
         searchRequest         SearchRequest,
         searchResEntry        SearchResultEntry,
         searchResDone         SearchResultDone,
         searchResRef          SearchResultReference,
         modifyRequest         ModifyRequest,
         modifyResponse        ModifyResponse,
         addRequest            AddRequest,
         addResponse           AddResponse,
         delRequest            DelRequest,
         delResponse           DelResponse,
         modDNRequest          ModifyDNRequest,
         modDNResponse         ModifyDNResponse,
         compareRequest        CompareRequest,
         compareResponse       CompareResponse,
         abandonRequest        AbandonRequest,
         extendedReq           ExtendedRequest,
         extendedResp          ExtendedResponse,
         ...,
         intermediateResponse  IntermediateResponse },
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('bindRequest', BindRequest().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('searchRequest', SearchRequest().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
    )


class LDAPIOD(univ.OctetString):
    """
    LDAPOID ::= OCTET STRING -- Constrained to <numericoid>
    """
    pass


class Control(univ.Sequence):
    """
    Control ::= SEQUENCE {
             controlType             LDAPOID,
             criticality             BOOLEAN DEFAULT FALSE,
             controlValue            OCTET STRING OPTIONAL }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('controlType', LDAPIOD()),
        namedtype.NamedType('criticality', univ.Boolean()),
        namedtype.OptionalNamedType('controlValue', univ.OctetString()))


class Controls(univ.Sequence):
    """
    Controls ::= SEQUENCE OF control Control
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('control', Control()),
        )


class LDAPMessage(univ.Sequence):
    """
    LDAPMessage ::= SEQUENCE {
             messageID       MessageID,
             protocolOp      CHOICE {
                  bindRequest           BindRequest,
                  bindResponse          BindResponse,
                  unbindRequest         UnbindRequest,
                  searchRequest         SearchRequest,
                  searchResEntry        SearchResultEntry,
                  searchResDone         SearchResultDone,
                  searchResRef          SearchResultReference,
                  modifyRequest         ModifyRequest,
                  modifyResponse        ModifyResponse,
                  addRequest            AddRequest,
                  addResponse           AddResponse,
                  delRequest            DelRequest,
                  delResponse           DelResponse,
                  modDNRequest          ModifyDNRequest,
                  modDNResponse         ModifyDNResponse,
                  compareRequest        CompareRequest,
                  compareResponse       CompareResponse,
                  abandonRequest        AbandonRequest,
                  extendedReq           ExtendedRequest,
                  extendedResp          ExtendedResponse,
                  ...,
                  intermediateResponse  IntermediateResponse },
             controls       [0] Controls OPTIONAL }

        MessageID ::= INTEGER (0 ..  maxInt)

        maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('messageID', univ.Integer() ),
        namedtype.NamedType('protocolOp', LDAPOp()),
        namedtype.OptionalNamedType('controls', Controls() ),
    )


if __name__ == '__main__':
    print('Testings')

    data = b'0B\x02\x01\x01`=\x02\x01\x03\x042uid=ocordes@UNI-BONN.DE,ou=Users,dc=uni-bonn,dc=de\x80\x04sdsd'

    #d = decoder.decode(data, asn1Spec=LDAPMessage())

    #print(d)
    print(data)

    saslcredentials = SaslCredentials()
    #saslcredentials['mechanism'] = ''
    saslcredentials['credentials'] = 'sdsd'


    authenticationchoice = AuthenticationChoice()
    #1authenticationchoice['simple'] = 'simple'
    authenticationchoice['sasl'] = saslcredentials

    #print(encoder.encode(authenticationchoice))

    bind_request = BindRequest()
    bind_request['version'] = 3
    bind_request['name'] = 'uid=ocordes@UNI-BONN.DE,ou=Users,dc=uni-bonn,dc=de'
    #bind_request['authentication'] = authenticationchoice


    #print(encoder.encode(bind_request))


    ldapmessage = LDAPMessage()
    ldapmessage['messageID'] = 1
    ldapmessage['protocolOp'] = bind_request
    lm = encoder.encode(ldapmessage)
    print(encoder.encode(ldapmessage))
    #print(encoder.encode(bind_request))
    print(decoder.decode(lm))
    print(decoder.decode(data))

    # <Sequence value object at 0x10c84f6d8 tagSet=
    #    <TagSet object at 0x10c84fd68 tags 0:32:16>
    #       subtypeSpec=<ConstraintsIntersection object at 0x10c785ba8>
    #       componentType=<NamedTypes object at 0x10c785c18 types >
    #       sizeSpec=<ConstraintsIntersection object at 0x10c785be0>
    #       payload [<Integer value object at 0x10c84fcc0 tagSet
    #         <TagSet object at 0x10c84f5f8 tags 0:0:2> payload [1]>,
    #            <Integer value object at 0x10c84fdd8 tagSet
    #              <TagSet object at 0x10c84fda0 tags 0:0:2-64:32:0> payload [3]>]>


    # <Sequence value object at 0x10c84fcc0 tagSet=
    #    <TagSet object at 0x10c84fb38 tags 0:32:16>
    #       subtypeSpec=<ConstraintsIntersection object at 0x10c785ba8>
    #       componentType=<NamedTypes object at 0x10c785c18 types >
    #       sizeSpec=<ConstraintsIntersection object at 0x10c785be0>
    #       payload [<Integer value object at 0x10c84f6d8 tagSet
    #         <TagSet object at 0x10c84f5f8 tags 0:0:2> payload [1]>,
    #            <Sequence value object at 0x10c84fac8 tagSet=<TagSet object at 0x10c84f898 tags 0:32:16> subtypeSpec=<ConstraintsIntersection object at 0x10c785ba8> componentType=<NamedTypes object at 0x10c785c18 types > sizeSpec=<ConstraintsIntersection object at 0x10c785be0> payload [<Integer value object at 0x10c84f748 tagSet <TagSet object at 0x10c84f5f8 tags 0:0:2> payload [3]>, <OctetString value object at 0x10c84f8d0 tagSet <TagSet object at 0x10c84f828 tags 0:0:4> encoding iso-8859-1 payload [uid=ocordes@UNI-...c=uni-bonn,dc=de]>, <SequenceOf value object at 0x10c84fa58 tagSet=<TagSet object at 0x10c84fa20 tags 0:32:16> subtypeSpec=<ConstraintsIntersection object at 0x10c785748> componentType=None sizeSpec=<ConstraintsIntersection object at 0x10c785780> payload [<OctetString value object at 0x10c84f940 tagSet <TagSet object at 0x10c84f828 tags 0:0:4> encoding iso-8859-1 payload []>, <OctetString value object at 0x10c84f9e8 tagSet <TagSet object at 0x10c84f828 tags 0:0:4> encoding iso-8859-1 payload [credential]>]>]>]>, b'
