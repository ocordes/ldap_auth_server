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


class RelativeLDAPDN(LDAPString):
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
    componentType = LDAPString()


class AttributeValueAssertion(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('attributeDesc', AttributeDescription()),
        namedtype.NamedType('assertionValue', AssertionValue())
    )


class AttributeValue(univ.OctetString):
    pass


class Attribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeDescription()),
        namedtype.NamedType('vals', univ.SetOf(
            componentType=AttributeValue()))
            #componentType=univ.OctetString()))
    )


class AttributeList(univ.SequenceOf):
    componentType = Attribute()


class URI(LDAPString):
    pass


class PartialAttribute(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('type', AttributeDescription()),
        namedtype.NamedType('vals', univ.SetOf(
            componentType=AttributeValue()))
    )


class PartialAttributeList(univ.SequenceOf):
    componentType = PartialAttribute()


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
    componentType = URI()
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
        #namedtype.OptionalNamedType('referral', Referral().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3)))
    )


class BindResponse(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 1))

    componentType = namedtype.NamedTypes(
        #namedtype.NamedType('resultCode', ResultCode()),
        namedtype.NamedType('resultCode',
         univ.Enumerated(
             namedValues=namedval.NamedValues(
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
                 ('other', 80)))),
        namedtype.NamedType('matchedDN', LDAPDN()),
        namedtype.NamedType('diagnosticMessage', LDAPString()),
        #namedtype.OptionalNamedType('referral', Referral().subtype(implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
        namedtype.OptionalNamedType('serverSaslCreds', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7)))
    )


#------------------------------------------------------------------------------
# UnbindRequest


class UnbindRequest(univ.Null):
    tagSet = univ.Null.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 2))


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
        namedtype.NamedType('substrings', univ.SequenceOf(componentType=univ.Choice(componentType=namedtype.NamedTypes(
            namedtype.NamedType('initial', AssertionValue().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
            namedtype.NamedType('any', AssertionValue().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
            namedtype.NamedType('final', AssertionValue().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)))
            )
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
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 3))
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('baseObject', LDAPDN()),
            namedtype.NamedType('scope', univ.Enumerated(namedValues=namedval.NamedValues(('baseObject', 0), ('singleLevel', 1), ('wholeSubtree', 2)))),
            namedtype.NamedType('derefAliases', univ.Enumerated(namedValues=namedval.NamedValues(('neverDerefAliases', 0), ('derefInSearching', 1), ('derefFindingBaseObj', 2), ('derefAlways', 3)))),
            namedtype.NamedType('sizeLimit', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, maxInt))),
            namedtype.NamedType('timeLimit', univ.Integer().subtype(subtypeSpec=constraint.ValueRangeConstraint(0, maxInt))),
            namedtype.NamedType('typesOnly', univ.Boolean()),
            namedtype.NamedType('filter', Filter()),
            namedtype.NamedType('attributes', AttributeSelection())
    )

#------------------------------------------------------------------------------
# SearchResultEntry

class SearchResultEntry(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 4))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('objectName', LDAPDN()),
        namedtype.NamedType('attributes', PartialAttributeList())
)


#------------------------------------------------------------------------------
# SearchResultDone

class SearchResultDone(LDAPResult):
    tagSet = LDAPResult.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 5))


#------------------------------------------------------------------------------
# SearchResultReference

class SearchResultReference(univ.SequenceOf):
    tagSet = univ.SequenceOf.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 19))
    componentType = URI()
    subtypeSpec=constraint.ValueSizeConstraint(1, MAX)

#------------------------------------------------------------------------------
# ModifyRequest

class ModifyRequest(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 6))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('object', LDAPDN()),
        namedtype.NamedType('changes',
            univ.SequenceOf(componentType=univ.Sequence(componentType=namedtype.NamedTypes(
                    namedtype.NamedType('operation',
                        univ.Enumerated(namedValues=namedval.NamedValues(
                            ('add', 0),
                            ('delete', 1),
                            ('replace', 2)))
                    ),
                    namedtype.NamedType('modification', PartialAttribute())
                )
            ))
       )
    )


#------------------------------------------------------------------------------
# ModifyResponse

class ModifyResponse(LDAPResult):
    tagSet = LDAPResult.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 7))


#------------------------------------------------------------------------------
# AddRequest

class AddRequest(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 8))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('entry', LDAPDN()),
        namedtype.NamedType('attributes', AttributeList())
    )


#------------------------------------------------------------------------------
# AddResponse

class AddResponse(LDAPResult):
    tagSet = LDAPResult.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 9))


#------------------------------------------------------------------------------
# DelRequest

class DelRequest(LDAPDN):
    tagSet = LDAPDN.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 10))


#------------------------------------------------------------------------------
# SearchResultDone

class DelResponse(LDAPResult):
    tagSet = LDAPResult.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 11))


#------------------------------------------------------------------------------
# ExtendedRequest

class ModifyDNRequest(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 12))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('entry', LDAPDN()),
        namedtype.NamedType('newrdn', RelativeLDAPDN()),
        namedtype.NamedType('deleteoldrdn', univ.Boolean()),
        namedtype.OptionalNamedType('newSuperior', LDAPDN().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))
)


#------------------------------------------------------------------------------
# ModifyDNResponse

class ModifyDNResponse(LDAPResult):
    tagSet = LDAPResult.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 13))


#------------------------------------------------------------------------------
# CompareRequest

class CompareRequest(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 14))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('entry', LDAPDN()),
        namedtype.NamedType('ava', AttributeValueAssertion())
)


#------------------------------------------------------------------------------
# CompareResponse

class CompareResponse(LDAPResult):
    tagSet = LDAPResult.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 15))


#------------------------------------------------------------------------------
# AbandonRequest

class AbandonRequest(MessageID):
    tagSet = MessageID.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 16))

#------------------------------------------------------------------------------
# ExtendedRequest

class ExtendedRequest(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 23))
    componentType = namedtype.NamedTypes(
            namedtype.NamedType('requestName', LDAPOID().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
            namedtype.OptionalNamedType('requestValue', univ.OctetString().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1)))
    )

#------------------------------------------------------------------------------
# IntermediateResponse

class ExtendedResponse(univ.Sequence):
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 24))
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
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 25))
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


class Controls2(univ.Sequence):
    """
    Controls ::= SEQUENCE OF control Control
    """
    tagSet = univ.Sequence.tagSet.tagImplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('control', Control()),
        )


class Controls(univ.OctetString):
    tagSet = univ.OctetString.tagSet.tagImplicitly(tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0))



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
            namedtype.NamedType('unbindRequest', UnbindRequest()),
            namedtype.NamedType('searchRequest', SearchRequest()),
            namedtype.NamedType('searchResEntry', SearchResultEntry()),
            namedtype.NamedType('searchResDone', SearchResultDone()),
            namedtype.NamedType('searchResRef', SearchResultReference()),
            namedtype.NamedType('modifyRequest', ModifyRequest()),
            namedtype.NamedType('modifyResponse', ModifyResponse()),
            namedtype.NamedType('addRequest', AddRequest()),
            namedtype.NamedType('addResponse', AddResponse()),
            namedtype.NamedType('delRequest', DelRequest()),
            namedtype.NamedType('delResponse', DelResponse()),
            namedtype.NamedType('modDNRequest', ModifyDNRequest()),
            namedtype.NamedType('modDNResponse', ModifyDNResponse()),
            namedtype.NamedType('compareRequest', CompareRequest()),
            namedtype.NamedType('compareResponse', CompareResponse()),
            namedtype.NamedType('abandonRequest', AbandonRequest()),
            namedtype.NamedType('extendedReq', ExtendedRequest()),
            namedtype.NamedType('extendedResp', ExtendedResponse()),
            namedtype.NamedType('intermediateResponse', IntermediateResponse())
            ))
        ),
        #namedtype.OptionalNamedType('controls', Controls().subtype(explicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0)))
        namedtype.OptionalNamedType('controls', Controls()),
    )


if __name__ == '__main__':
    print('Testings')

    data = b'0B\x02\x01\x01`=\x02\x01\x03\x042uid=ocordes@UNI-BONN.DE,ou=Users,dc=uni-bonn,dc=de\x80\x04sdsd'

    data = b"0\x82\x02x\x02\x01\x02d\x82\x02q\x04,uid=omc,ou=People,dc=astro,dc=uni-bonn,dc=de0\x82\x02?0n\x04\x0bobjectClass1_\x04\x16inetLocalMailRecipient\x04\x0cposixAccount\x04\rinetOrgPerson\x04\x14organizationalPerson\x04\x06person\x04\nhostObject0\x19\x04\nloginShell1\x0b\x04\t/bin/bash0\x12\x04\tgidNumber1\x05\x04\x031000\x15\x04\x02cn1\x0f\x04\rOliver Cordes0\x0e\x04\x02sn1\x08\x04\x06Cordes0\x15\x04\tgivenName1\x08\x04\x06Oliver0\x1e\x04\x10mailLocalAddress1\n\x04\x08omcordes0\x18\x04\x0cemployeeType1\x08\x04\x06Intern0\x13\x04\tuidNumber1\x06\x04\x0419990'\x04\x04host1\x1f\x04\x07desktop\x04\x05ebhis\x04\x06portal\x04\x05theli0\x1d\x04\rhomeDirectory1\x0c\x04\n/users/omc08\x04\x0cuserPassword1(\x04&{SSHA}/W0okeqgj7NbCkymTDzm9FyO9IFSeEho00\x04\x04mail1(\x04\x15omc@astro.uni-bonn.de\x04\x0focordes@gmx.net0#\x04\x10departmentNumber1\x0f\x04\x01F\x04\x01M\x04\x01N\x04\x01R\x04\x01T0*\x04\x12mailRoutingAddress1\x14\x04\x12ocordes@freenet.de0\x0c\x04\x03uid1\x05\x04\x03omc0\x0c\x02\x01\x02e\x07\n\x01\x00\x04\x00\x04\x00"

    debug.setLogger(debug.Debug('all'))
    x, _ = decoder.decode(data, LDAPMessage())
    print(x)
    sys.exit(0)

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




    x, _ = decoder.decode(data, LDAPMessage())
    print(x.prettyPrint())
    x, _ = decoder.decode(lm, LDAPMessage())
    print(x.prettyPrint())



    #data = b'0\x05\x02\x01\x03B\x00'
    data = b'0\x0c\x02\x01\x01a\x07\n\x01\x00\x04\x00\x04\x00'
    print(data)
    bind_response = BindResponse()
    bind_response['resultCode'] = 'success'
    bind_response['matchedDN'] = ''
    bind_response['diagnosticMessage'] = ''
    ldapmessage = LDAPMessage()
    ldapmessage['messageID'] = 1
    ldapmessage['protocolOp'] = bind_response
    lm = encoder.encode(ldapmessage)
    print('Self')
    print(lm)
    print(' '.join([ '%03i' % i for i in lm]))
    ##debug.setLogger(debug.Debug('all'))
    x, _ = decoder.decode(data, LDAPMessage())
    print(x.prettyPrint())
    sys.exit(0)

    #x, _ = decoder.decode(data)
    ##debug.setLogger(debug.Debug('all'))
    ##x, _ = decoder.decode(data,LDAPMessage())

    ##print(x.prettyPrint())

    debug.setLogger(debug.Debug('all'))
    data = b'\n\x01\x00\x04\x00\x04\x00'
    data = lm

    x, _ = decoder.decode(data)
    print(x.prettyPrint())
