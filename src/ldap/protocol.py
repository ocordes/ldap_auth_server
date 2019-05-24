"""

src/ldap/protocol.py

written by: Oliver Cordes 2019-05-22
changed by: Oliver Cordes 2019-05-23
"""

import os, sys

# Imports from pyasn1
from pyasn1.type import tag, namedtype, namedval, univ, constraint
from pyasn1.codec.ber import encoder, decoder

from pyasn1 import debug
#debug.setLogger(debug.Debug('all'))


# https://tools.ietf.org/html/rfc4511

maxInt = univ.Integer(2147483647)
MAX = maxInt

class LDAPString(univ.OctetString):
    pass


class LDAPDN(LDAPString):
    pass


class LDAPOID(univ.OctetString):
    pass


class MessageID(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(0, maxInt)


class Version(univ.Integer):
    subtypeSpec = constraint.ValueRangeConstraint(1, 127)


class AssertionValue(univ.OctetString):
    pass


class AttributeDescription(LDAPString):
    pass


class AttributeSelection(univ.SequenceOf):
    componentType = namedtype.NamedType('selector', LDAPString())


class AttributeValueAssertion(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('attributeDesc', AttributeDescription()),
        namedtype.NamedType('assertionValue', AssertionValue())
    )


class URI(LDAPString):
    pass


# special types

#------------------------------------------------------------------------------
# BindRequest

class SaslCredentials(univ.Sequence):
    """
    SaslCredentials ::= SEQUENCE {
             mechanism               LDAPString,
             credentials             OCTET STRING OPTIONAL }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('mechanism', LDAPString()),
        namedtype.OptionalNamedType('credentials', univ.OctetString()),
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
        namedtype.NamedType('simple', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('sasl', SaslCredentials().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)))
    )


class BindRequest(univ.Sequence):
    """
    BindRequest ::= [APPLICATION 0] SEQUENCE {
             version                 INTEGER (1 ..  127),
             name                    LDAPDN,
             authentication          AuthenticationChoice }
    """
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Version()),
        namedtype.NamedType('name', LDAPDN()),
        namedtype.NamedType('authentication', AuthenticationChoice()),
    )
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0))


#------------------------------------------------------------------------------
# BindResponse

class Referral(univ.SequenceOf):
    componentType = namedtype.NamedType('uri', URI())
    subtypeSpec=constraint.ValueSizeConstraint(1, MAX)


class ResultCode(univ.Enumerated):
    componentType = namedValues=namedval.NamedValues(
            ('success', 0),
            ('operationsError', 1),
            ('protocolError', 2),
            ('timeLimitExceeded', 3),
            ('sizeLimitExceeded', 4),
            ('compareFalse', 5),
            ('compareTrue', 6),
            ('authMethodNotSupported', 7),
            ('strongerAuthRequired', 8),
            ('referral', 10),
            ('adminLimitExceeded', 11),
            ('unavailableCriticalExtension', 12),
            ('confidentialityRequired', 13),
            ('saslBindInProgress', 14),
            ('noSuchAttribute', 16),
            ('undefinedAttributeType', 17),
            ('inappropriateMatching', 18),
            ('constraintViolation', 19),
            ('attributeOrValueExists', 20),
            ('invalidAttributeSyntax', 21),
            ('noSuchObject', 32),
            ('aliasProblem', 33),
            ('invalidDNSyntax', 34),
            ('aliasDereferencingProblem', 36),
            ('inappropriateAuthentication', 48),
            ('invalidCredentials', 49),
            ('insufficientAccessRights', 50),
            ('busy', 51),
            ('unavailable', 52),
            ('unwillingToPerform', 53),
            ('loopDetect', 54),
            ('namingViolation', 64),
            ('objectClassViolation', 65),
            ('notAllowedOnNonLeaf', 66),
            ('notAllowedOnRDN', 67),
            ('entryAlreadyExists', 68),
            ('objectClassModsProhibited', 69),
            ('affectsMultipleDSAs', 71),
            ('other', 80)
        )


class LDAPResult(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('resultCode', ResultCode()),
        namedtype.NamedType('matchedDN', LDAPDN()),
        namedtype.NamedType('diagnosticMessage', LDAPString()),
        namedtype.OptionalNamedType('referral', Referral().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)))
    )


class BindResponse(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagExplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 1))
    componentType = namedtype.NamedTypes(
        #namedtype.NamedType('resultCode', ResultCode()),
        namedtype.NamedType('resultCode', univ.Integer()),
        # univ.Enumerated(
        #     namedValues=namedval.NamedValues(
        #         ('success', 0),
        #         ('operationsError', 1),
        #         ('protocolError', 2),
        #         ('timeLimitExceeded', 3),
        #         ('sizeLimitExceeded', 4),
        #         ('compareFalse', 5),
        #         ('compareTrue', 6),
        #         ('authMethodNotSupported', 7),
        #         ('strongerAuthRequired', 8),
        #         ('referral', 10),
        #         ('adminLimitExceeded', 11),
        #         ('unavailableCriticalExtension', 12),
        #         ('confidentialityRequired', 13),
        #         ('saslBindInProgress', 14),
        #         ('noSuchAttribute', 16),
        #         ('undefinedAttributeType', 17),
        #         ('inappropriateMatching', 18),
        #         ('constraintViolation', 19),
        #         ('attributeOrValueExists', 20),
        #         ('invalidAttributeSyntax', 21),
        #         ('noSuchObject', 32),
        #         ('aliasProblem', 33),
        #         ('invalidDNSyntax', 34),
        #         ('aliasDereferencingProblem', 36),
        #         ('inappropriateAuthentication', 48),
        #         ('invalidCredentials', 49),
        #         ('insufficientAccessRights', 50),
        #         ('busy', 51),
        #         ('unavailable', 52),
        #         ('unwillingToPerform', 53),
        #         ('loopDetect', 54),
        #         ('namingViolation', 64),
        #         ('objectClassViolation', 65),
        #         ('notAllowedOnNonLeaf', 66),
        #         ('notAllowedOnRDN', 67),
        #         ('entryAlreadyExists', 68),
        #         ('objectClassModsProhibited', 69),
        #         ('affectsMultipleDSAs', 71),
        #         ('other', 80)))),
        namedtype.NamedType('matchedDN', LDAPDN()),
        namedtype.NamedType('diagnosticMessage', LDAPString()),
        namedtype.OptionalNamedType('referral', Referral().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
        namedtype.OptionalNamedType('serverSaslCreds', univ.OctetString().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)))
    )


#------------------------------------------------------------------------------
# SearchRequest

class MatchingRuleId(LDAPString):
    pass


class MatchingRuleAssertion(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.OptionalNamedType('matchingRule', MatchingRuleId().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType('type', AttributeDescription().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
        namedtype.NamedType('matchValue', AssertionValue().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
        namedtype.DefaultedNamedType('dnAttributes', univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)).subtype(value=0))
    )


class SubstringFilter(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeDescription()),
        namedtype.NamedType('substrings', univ.SequenceOf(componentType=namedtype.NamedType('substring', univ.Choice(componentType=namedtype.NamedTypes(
            namedtype.NamedType('initial', AssertionValue().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
            namedtype.NamedType('any', AssertionValue().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
            namedtype.NamedType('final', AssertionValue().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)))
            ))
        )).subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX)))
    )


class Filter(univ.Choice):
    pass

Filter.componentType = namedtype.NamedTypes(
        namedtype.NamedType('and', univ.SetOf(componentType=namedtype.NamedType('filter', Filter())).subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX)).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.NamedType('or', univ.SetOf(componentType=namedtype.NamedType('filter', Filter())).subtype(subtypeSpec=constraint.ValueSizeConstraint(1, MAX)).subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.NamedType('not', Filter().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))),
        namedtype.NamedType('equalityMatch', AttributeValueAssertion().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))),
        namedtype.NamedType('substrings', SubstringFilter().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4))),
        namedtype.NamedType('greaterOrEqual', AttributeValueAssertion().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 5))),
        namedtype.NamedType('lessOrEqual', AttributeValueAssertion().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 6))),
        namedtype.NamedType('present', AttributeDescription().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
        namedtype.NamedType('approxMatch', AttributeValueAssertion().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 8))),
        namedtype.NamedType('extensibleMatch', MatchingRuleAssertion().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 9)))
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
             equalityMatch   [3] AttributeValueAssertion,
             substrings      [4] SubstringFilter,
             greaterOrEqual  [5] AttributeValueAssertion,
             lessOrEqual     [6] AttributeValueAssertion,
             present         [7] AttributeDescription,
             approxMatch     [8] AttributeValueAssertion,
             extensibleMatch [9] MatchingRuleAssertion,
             ...  }

        SubstringFilter ::= SEQUENCE {
             type           AttributeDescription,
             substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
                  initial [0] AssertionValue,  -- can occur at most once
                  any     [1] AssertionValue,
                  final   [2] AssertionValue } -- can occur at most once
             }

        MatchingRuleAssertion ::= SEQUENCE {
             matchingRule    [1] MatchingRuleId OPTIONAL,
             type            [2] AttributeDescription OPTIONAL,
             matchValue      [3] AssertionValue,
             dnAttributes    [4] BOOLEAN DEFAULT FALSE }

    """
    tagSet = univ.Sequence.tagSet.tagExplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 3))
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('baseObject', univ.OctetString()),
    )


#------------------------------------------------------------------------------
# SearchResultDone

class SearchResultDone(LDAPResult):
    tagSet = LDAPResult.tagSet.tagExplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 5))


#------------------------------------------------------------------------------
# SearchResultDone

class DelRequest(LDAPDN):
    tagSet = LDAPDN.tagSet.tagExplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 10))


#------------------------------------------------------------------------------
# SearchResultDone

class DelResponse(LDAPResult):
    tagSet = LDAPResult.tagSet.tagExplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 11))


#------------------------------------------------------------------------------
# ExtendedRequest

class ExtendedRequest(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagExplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 23))
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('requestName', LDAPOID().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
            namedtype.OptionalNamedType('requestValue', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)))
    )

#------------------------------------------------------------------------------
# IntermediateResponse

class ExtendedResponse(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagExplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 24))
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('resultCode',
                univ.Enumerated(namedValues=namedval.NamedValues(('success', 0), ('operationsError', 1), ('protocolError', 2), ('timeLimitExceeded', 3), ('sizeLimitExceeded', 4), ('compareFalse', 5), ('compareTrue', 6), ('authMethodNotSupported', 7), ('strongerAuthRequired', 8), ('referral', 10), ('adminLimitExceeded', 11), ('unavailableCriticalExtension', 12), ('confidentialityRequired', 13), ('saslBindInProgress', 14), ('noSuchAttribute', 16), ('undefinedAttributeType', 17), ('inappropriateMatching', 18), ('constraintViolation', 19), ('attributeOrValueExists', 20), ('invalidAttributeSyntax', 21), ('noSuchObject', 32), ('aliasProblem', 33), ('invalidDNSyntax', 34), ('aliasDereferencingProblem', 36), ('inappropriateAuthentication', 48), ('invalidCredentials', 49), ('insufficientAccessRights', 50), ('busy', 51), ('unavailable', 52), ('unwillingToPerform', 53), ('loopDetect', 54), ('namingViolation', 64), ('objectClassViolation', 65), ('notAllowedOnNonLeaf', 66), ('notAllowedOnRDN', 67), ('entryAlreadyExists', 68), ('objectClassModsProhibited', 69), ('affectsMultipleDSAs', 71), ('other', 80)))),
            namedtype.NamedType('matchedDN', LDAPDN()),
            namedtype.NamedType('diagnosticMessage', LDAPString()),
            namedtype.OptionalNamedType('referral', Referral().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
            namedtype.OptionalNamedType('responseName', LDAPOID().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10))),
            namedtype.OptionalNamedType('responseValue', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 11)))
    )

#------------------------------------------------------------------------------
# IntermediateResponse

class IntermediateResponse(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagExplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 25))
    componentType = namedtype.NamedTypes(
            namedtype.OptionalNamedType('responseName', LDAPOID().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
            namedtype.OptionalNamedType('responseValue', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)))
    )


#------------------------------------------------------------------------------
# LDAPOp

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
        namedtype.NamedType('bindRequest', BindRequest()),
        namedtype.NamedType('bindResponse',BindResponse()),
        namedtype.NamedType('searchRequest', SearchRequest()),
        namedtype.NamedType('searchResDone', SearchResultDone()),
        namedtype.NamedType('delRequest', DelRequest()),
        namedtype.NamedType('delResponse', DelResponse()),
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
    # componentType = namedtype.NamedTypes(
    #     namedtype.NamedType('messageID', MessageID() ),
    #     namedtype.NamedType('protocolOp', LDAPOp()),
    #     namedtype.OptionalNamedType('controls', Controls().subtype(
    #         implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
    # )
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('messageID', MessageID()),
        namedtype.NamedType('protocolOp', univ.Choice(componentType=namedtype.NamedTypes(
            namedtype.NamedType('bindRequest', BindRequest()),
            namedtype.NamedType('bindResponse', BindResponse()),
            #namedtype.NamedType('unbindRequest', UnbindRequest()),
            namedtype.NamedType('searchRequest', SearchRequest()),
            #namedtype.NamedType('searchResEntry', SearchResultEntry()),
            namedtype.NamedType('searchResDone', SearchResultDone()),
            #namedtype.NamedType('searchResRef', SearchResultReference()),
            #namedtype.NamedType('modifyRequest', ModifyRequest()),
            #namedtype.NamedType('modifyResponse', ModifyResponse()),
            #namedtype.NamedType('addRequest', AddRequest()),
            #namedtype.NamedType('addResponse', AddResponse()),
            namedtype.NamedType('delRequest', DelRequest()),
            namedtype.NamedType('delResponse', DelResponse()),
            #namedtype.NamedType('modDNRequest', ModifyDNRequest()),
            #namedtype.NamedType('modDNResponse', ModifyDNResponse()),
            #namedtype.NamedType('compareRequest', CompareRequest()),
            #namedtype.NamedType('compareResponse', CompareResponse()),
            #namedtype.NamedType('abandonRequest', AbandonRequest()),
            namedtype.NamedType('extendedReq', ExtendedRequest()),
            namedtype.NamedType('extendedResp', ExtendedResponse()),
            namedtype.NamedType('intermediateResponse', IntermediateResponse())
            ))
        ),
        namedtype.OptionalNamedType('controls', Controls().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))
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
    authenticationchoice['simple'] = 'sdsd'
    #authenticationchoice['sasl'] = saslcredentials

    lm = encoder.encode(authenticationchoice)

    bind_request = BindRequest()
    bind_request['version'] = 3
    bind_request['name'] = 'uid=ocordes@UNI-BONN.DE,ou=Users,dc=uni-bonn,dc=de'
    bind_request['authentication'] = authenticationchoice


    lm = encoder.encode(bind_request)


    print('Hallo')

    ldapmessage = LDAPMessage()
    ldapmessage['messageID'] = 1
    ldapmessage['protocolOp'] = bind_request
    lm = encoder.encode(ldapmessage)
    print(lm)



    print(lm)
    #print(encoder.encode(bind_request))
    print('Decoding atrificial message')
    #print(decoder.decode(lm))
    print('Decoding real message')
    #print(decoder.decode(data))

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


    x, _ = decoder.decode(data, LDAPMessage())
    print(x.prettyPrint())
    x, _ = decoder.decode(lm, LDAPMessage())
    print(x.prettyPrint())



    #data = b'0\x05\x02\x01\x03B\x00'
    data = b'0\x0c\x02\x01\x01a\x07\n\x01\x00\x04\x00\x04\x00'
    print(data)
    bind_response = BindResponse()
    bind_response['resultCode'] = 0
    bind_response['matchedDN'] = ''
    bind_response['diagnosticMessage'] = ''
    ldapmessage = LDAPMessage()
    ldapmessage['messageID'] = 1
    ldapmessage['protocolOp'] = bind_response
    lm = encoder.encode(ldapmessage)
    print(lm)
    debug.setLogger(debug.Debug('all'))
    x, _ = decoder.decode(data, LDAPMessage())
    #print(x.prettyPrint())
    sys.exit(0)

    #x, _ = decoder.decode(data)
    debug.setLogger(debug.Debug('all'))
    x, _ = decoder.decode(data,LDAPMessage())

    print(x.prettyPrint())


    data = b'\n\x01\x00\x04\x00\x04\x00'

    x, _ = decoder.decode(data)
    print(x.prettyPrint())
