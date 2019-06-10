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


class LDAPDN(LDAPString):
    pass


class MessageID(Integer):
    # MessageID ::= INTEGER (0 ..  maxInt)
    pass


class LDAPOID(OctetString):
    pass


class RelativeLDAPDN(LDAPString):
    pass


class AttributeDescription(LDAPString):
    pass


class AttributeValue(OctetString):
    pass


class AssertionValue(OctetString):
    pass


class AttributeValueAssertion(Sequence):
    # AttributeValueAssertion ::= SEQUENCE {
    #     attributeDesc   AttributeDescription,
    #     assertionValue  AssertionValue }
    namedValues = NamedValues(NamedType('attributeDesc', AttributeDescription()),
                               NamedType('assertionValue', AssertionValue()))


class MatchingRuleId(LDAPString):
    # MatchingRuleId ::= LDAPString
    pass


class Vals(Set):
    # vals       SET OF value AttributeValue }
    components = AttributeValue()




class PartialAttribute(Sequence):
    # PartialAttribute ::= SEQUENCE {
    #     type       AttributeDescription,
    #     vals       SET OF value AttributeValue }
    namedValues = NamedValues(NamedType('type', AttributeDescription()),
                               NamedType('vals', Vals()))


class Attribute(Sequence):
    # Attribute ::= PartialAttribute(WITH COMPONENTS {
    #     ...,
    #     vals (SIZE(1..MAX))})
    namedValues = NamedValues(NamedType('type', AttributeDescription()),
                               NamedType('vals', Vals()))


class AttributeList(Set):
    # AttributeList ::= SEQUENCE OF attribute Attribute
    components = Attribute()


class Simple(OctetString):
    # simple                  [0] OCTET STRING,
    tag = Tag(tagClassContext, tagFormatSimple, 0)


class Credentials(OctetString):
    # credentials             OCTET STRING
    pass


class SaslCredentials(Sequence):
    # SaslCredentials ::= SEQUENCE {
    #  mechanism               LDAPString,
    #  credentials             OCTET STRING OPTIONAL }
    tag = Tag(tagClassContext, tagFormatConstructed, 3)
    namedValues = NamedValues(NamedType('mechanism', LDAPString()),
                               OptionalNamedType('credentials', Credentials()))



class AuthenticationChoice(Choice):
    # AuthenticationChoice ::= CHOICE {
    #     simple                  [0] OCTET STRING,
    #                             -- 1 and 2 reserved
    #     sasl                    [3] SaslCredentials,
    # ... }
    namedValues = NamedValues(NamedType('simple', Simple()),
                               NamedType('sasl', SaslCredentials()))


class Version(Integer):
    # version                 INTEGER (1 ..  127),
    pass


class ResultCode(Enumerated):
    # resultCode         ENUMERATED {
    #     success                      (0),
    #     operationsError              (1),
    #     protocolError                (2),
    #     timeLimitExceeded            (3),
    #     sizeLimitExceeded            (4),
    #     compareFalse                 (5),
    #     compareTrue                  (6),
    #     authMethodNotSupported       (7),
    #     strongerAuthRequired         (8),
    #          -- 9 reserved --
    #     referral                     (10),
    #     adminLimitExceeded           (11),
    #     unavailableCriticalExtension (12),
    #     confidentialityRequired      (13),
    #     saslBindInProgress           (14),
    #     noSuchAttribute              (16),
    #     undefinedAttributeType       (17),
    #     inappropriateMatching        (18),
    #     constraintViolation          (19),
    #     attributeOrValueExists       (20),
    #     invalidAttributeSyntax       (21),
    #          -- 22-31 unused --
    #     noSuchObject                 (32),
    #     aliasProblem                 (33),
    #     invalidDNSyntax              (34),
    #          -- 35 reserved for undefined isLeaf --
    #     aliasDereferencingProblem    (36),
    #          -- 37-47 unused --
    #     inappropriateAuthentication  (48),
    #     invalidCredentials           (49),
    #     insufficientAccessRights     (50),
    #     busy                         (51),
    #     unavailable                  (52),
    #     unwillingToPerform           (53),
    #     loopDetect                   (54),
    #          -- 55-63 unused --
    #     namingViolation              (64),
    #     objectClassViolation         (65),
    #     notAllowedOnNonLeaf          (66),
    #     notAllowedOnRDN              (67),
    #     entryAlreadyExists           (68),
    #     objectClassModsProhibited    (69),
    #          -- 70 reserved for CLDAP --
    #     affectsMultipleDSAs          (71),
    #          -- 72-79 unused --
    #     other                        (80),
    #     ...  }
    #
    #     from IANA ldap-parameters:
    #     lcupResourcesExhausted        113        IESG                             [RFC3928]
    #     lcupSecurityViolation         114        IESG                             [RFC3928]
    #     lcupInvalidData               115        IESG                             [RFC3928]
    #     lcupUnsupportedScheme         116        IESG                             [RFC3928]
    #     lcupReloadRequired            117        IESG                             [RFC3928]
    #     canceled                      118        IESG                             [RFC3909]
    #     noSuchOperation               119        IESG                             [RFC3909]
    #     tooLate                       120        IESG                             [RFC3909]
    #     cannotCancel                  121        IESG                             [RFC3909]
    #     assertionFailed               122        IESG                             [RFC4528]
    #     authorizationDenied           123        WELTMAN                          [RFC4370]
    #     e-syncRefreshRequired         4096       [Kurt_Zeilenga] [Jong_Hyuk_Choi] [RFC4533]
    valuemap = ValueMap(('success', 0),
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
                              ('loopDetected', 54),
                              ('namingViolation', 64),
                              ('objectClassViolation', 65),
                              ('notAllowedOnNonLeaf', 66),
                              ('notAllowedOnRDN', 67),
                              ('entryAlreadyExists', 68),
                              ('objectClassModsProhibited', 69),
                              ('affectMultipleDSAs', 71),
                              ('other', 80),
                              ('lcupResourcesExhausted', 113),
                              ('lcupSecurityViolation', 114),
                              ('lcupInvalidData', 115),
                              ('lcupUnsupportedScheme', 116),
                              ('lcupReloadRequired', 117),
                              ('canceled', 118),
                              ('noSuchOperation', 119),
                              ('tooLate', 120),
                              ('cannotCancel', 121),
                              ('assertionFailed', 122),
                              ('authorizationDenied', 123),
                              ('e-syncRefreshRequired', 4096))


class URI(LDAPString):
    # URI ::= LDAPString     -- limited to characters permitted in
    #                      -- URIs
    pass


class Referral(Set):
    # Referral ::= SEQUENCE SIZE (1..MAX) OF uri URI
    tag = Tag(tagClassContext, tagFormatConstructed, 3)
    components = URI()


class ServerSaslCreds(OctetString):
    # serverSaslCreds    [7] OCTET STRING OPTIONAL
    tag = Tag(tagClassContext, tagFormatSimple, 7)


class LDAPResult(Sequence):
    # LDAPResult ::= SEQUENCE {
    #     resultCode         ENUMERATED {
    #         success                      (0),
    #         operationsError              (1),
    #         protocolError                (2),
    #         timeLimitExceeded            (3),
    #         sizeLimitExceeded            (4),
    #         compareFalse                 (5),
    #         compareTrue                  (6),
    #         authMethodNotSupported       (7),
    #         strongerAuthRequired         (8),
    #              -- 9 reserved --
    #         referral                     (10),
    #         adminLimitExceeded           (11),
    #         unavailableCriticalExtension (12),
    #         confidentialityRequired      (13),
    #         saslBindInProgress           (14),
    #         noSuchAttribute              (16),
    #         undefinedAttributeType       (17),
    #         inappropriateMatching        (18),
    #         constraintViolation          (19),
    #         attributeOrValueExists       (20),
    #         invalidAttributeSyntax       (21),
    #              -- 22-31 unused --
    #         noSuchObject                 (32),
    #         aliasProblem                 (33),
    #         invalidDNSyntax              (34),
    #              -- 35 reserved for undefined isLeaf --
    #         aliasDereferencingProblem    (36),
    #              -- 37-47 unused --
    #         inappropriateAuthentication  (48),
    #         invalidCredentials           (49),
    #         insufficientAccessRights     (50),
    #         busy                         (51),
    #         unavailable                  (52),
    #         unwillingToPerform           (53),
    #         loopDetect                   (54),
    #              -- 55-63 unused --
    #         namingViolation              (64),
    #         objectClassViolation         (65),
    #         notAllowedOnNonLeaf          (66),
    #         notAllowedOnRDN              (67),
    #         entryAlreadyExists           (68),
    #         objectClassModsProhibited    (69),
    #              -- 70 reserved for CLDAP --
    #         affectsMultipleDSAs          (71),
    #              -- 72-79 unused --
    #         other                        (80),
    #         ...  },
    #     matchedDN          LDAPDN,
    #     diagnosticMessage  LDAPString,
    #     referral           [3] Referral OPTIONAL }
    namedValues = NamedValues(NamedType('resultCode', ResultCode()),
                               NamedType('matchedDN', LDAPDN()),
                               NamedType('diagnosticMessage', LDAPString()),
                               OptionalNamedType('referral', Referral()))


class Criticality(Boolean):
    # criticality             BOOLEAN DEFAULT FALSE
    #defaultValue = False
    pass


class ControlValue(OctetString):
    # controlValue            OCTET STRING
    pass


class Control(Sequence):
    # Control ::= SEQUENCE {
    #     controlType             LDAPOID,
    #     criticality             BOOLEAN DEFAULT FALSE,
    #     controlValue            OCTET STRING OPTIONAL }
    namedValues = NamedValues(NamedType('controlType', LDAPOID()),
                               NamedType('criticality', Criticality()),
                               OptionalNamedType('controlValue', ControlValue()))


class Controls(Set):
    # Controls ::= SEQUENCE OF control Control
    tag = Tag(tagClassContext, tagFormatConstructed, 0)
    components = Control()




class BaseObject(LDAPDN):
    pass


class Scope(Enumerated):
    valuemap = ValueMap(('baseObject', 0),
                        ('singleLevel', 1),
                        ('wholeSubtree', 2))


class DerefAliases(Enumerated):
    valuemap = ValueMap(('neverDerefAliases', 0),
                        ('derefInSearching', 1),
                        ('derefFindingBaseObj', 2),
                        ('derefAlways', 3))


class SizeLimit(Integer):
    pass


class TimeLimit(Integer):
    pass


class TypesOnly(Boolean):
    pass


class Selector(LDAPString):
    #     -- The LDAPString is constrained to
    #     -- <attributeSelector> in Section 4.5.1.8

    # subtypeSpec = LDAPString.subtypeSpec + attributeSelectorConstraint
    pass


class AttributeSelection(SequenceOf):
    # AttributeSelection ::= SEQUENCE OF selector LDAPString
    #     -- The LDAPString is constrained to
    #     -- <attributeSelector> in Section 4.5.1.8
    components = Selector()


class MatchingRule(MatchingRuleId):
    # matchingRule    [1] MatchingRuleId
    tag = Tag(tagClassContext, tagFormatSimple, 1)


class Type(AttributeDescription):
    # type            [2] AttributeDescription
    tag = Tag(tagClassContext, tagFormatSimple, 2)


class MatchValue(AssertionValue):
    # matchValue      [3] AssertionValue,
    tag = Tag(tagClassContext, tagFormatSimple, 3)


class DnAttributes(Boolean):
    # dnAttributes    [4] BOOLEAN DEFAULT FALSE }
    tag = Tag(tagClassContext, tagFormatSimple, 4)
    #defaultValue = Boolean(False)


class MatchingRuleAssertion(Sequence):
    # MatchingRuleAssertion ::= SEQUENCE {
    #     matchingRule    [1] MatchingRuleId OPTIONAL,
    #     type            [2] AttributeDescription OPTIONAL,
    #     matchValue      [3] AssertionValue,
    #     dnAttributes    [4] BOOLEAN DEFAULT FALSE }
    namedValues = NamedValues(OptionalNamedType('matchingRule', MatchingRule()),
                               OptionalNamedType('type', Type()),
                               NamedType('matchValue', MatchValue()),
                               NamedType('dnAttributes', DnAttributes()))

class Initial(AssertionValue):
    # initial [0] AssertionValue,  -- can occur at most once
    tag = Tag(tagClassContext, tagFormatSimple, 0)


class Any(AssertionValue):
    # any [1] AssertionValue,
    tag = Tag(tagClassContext, tagFormatSimple, 1)


class Final(AssertionValue):
    # final [1] AssertionValue,  -- can occur at most once
    tag = Tag(tagClassContext, tagFormatSimple, 2)


class Substring(Choice):
    # substring CHOICE {
    #     initial [0] AssertionValue,  -- can occur at most once
    #     any     [1] AssertionValue,
    #     final   [2] AssertionValue } -- can occur at most once
    #     }
    namedValues = NamedValues(NamedType('initial', Initial()),
                               NamedType('any', Any()),
                               NamedType('final', Final()))


class Substrings(Set):
    # substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
    # ...
    # }
    #subtypeSpec = SequenceOf.subtypeSpec + size1ToMaxConstraint
    components = Substring()


class SubstringFilter(Sequence):
    #     SubstringFilter ::= SEQUENCE {
    #         type           AttributeDescription,
    #         substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
    #             initial [0] AssertionValue,  -- can occur at most once
    #             any     [1] AssertionValue,
    #             final   [2] AssertionValue } -- can occur at most once
    #             }
    tag = Tag(tagClassContext, tagFormatConstructed, 4)
    namedValues = NamedValues(NamedType('type', AttributeDescription()),
                               NamedType('substrings', Substrings()))


class Filter(Choice):
    pass


class And(Set):
    tag = Tag(tagClassContext, tagFormatConstructed, 0)
    components = NamedType('filter', Filter())


class Or(Set):
    # or              [1] SET SIZE (1..MAX) OF filter Filter
    tag = Tag(tagClassContext, tagFormatConstructed, 1)
    #subtypeSpec = SetOf.subtypeSpec + size1ToMaxConstraint
    components = NamedType('filter', Filter())


class Not(Choice):
    # not             [2] Filter
    tag = Tag(tagClassContext, tagFormatConstructed, 2)  # as per RFC4511 page 23
    namedValues = NamedValues(NamedType('filter', Filter()))


class EqualityMatch(AttributeValueAssertion):
    # equalityMatch   [3] AttributeValueAssertion
    #tag = Tag(tagClassContext, tagFormatConstructed, 3)
    tag = Tag(tagClassContext, tagFormatSimple, 3)


class GreaterOrEqual(AttributeValueAssertion):
    # greaterOrEqual  [5] AttributeValueAssertion
    #tag = Tag(tagClassContext, tagFormatConstructed, 5)
    tag = Tag(tagClassContext, tagFormatSimple, 5)


class LessOrEqual(AttributeValueAssertion):
    # lessOrEqual     [6] AttributeValueAssertion
    #tag = Tag(tagClassContext, tagFormatConstructed, 6)
    tag = Tag(tagClassContext, tagFormatSimple, 6)


class Present(AttributeDescription):
    # present         [7] AttributeDescription
    tag = Tag(tagClassContext, tagFormatSimple, 7)


class ApproxMatch(AttributeValueAssertion):
    # approxMatch     [8] AttributeValueAssertion
    #tag = Tag(tagClassContext, tagFormatConstructed, 8)
    tag = Tag(tagClassContext, tagFormatSimple, 8)


class ExtensibleMatch(MatchingRuleAssertion):
    # extensibleMatch [9] MatchingRuleAssertion
    #tag = Tag(tagClassContext, tagFormatConstructed, 9)
    tag = Tag(tagClassContext, tagFormatSimple, 9)



# Filter ::= CHOICE {
    #     and             [0] SET SIZE (1..MAX) OF filter Filter,
    #     or              [1] SET SIZE (1..MAX) OF filter Filter,
    #     not             [2] Filter,
    #     equalityMatch   [3] AttributeValueAssertion,
    #     substrings      [4] SubstringFilter,
    #     greaterOrEqual  [5] AttributeValueAssertion,
    #     lessOrEqual     [6] AttributeValueAssertion,
    #     present         [7] AttributeDescription,
    #     approxMatch     [8] AttributeValueAssertion,
    #     extensibleMatch [9] MatchingRuleAssertion,
    #          ...  }
Filter.namedValues = NamedValues(
                        NamedType('and', And()),
                        NamedType('or', Or()),
                        NamedType('notFilter', Not()),
                        NamedType('equalityMatch', EqualityMatch()),
                        NamedType('substringFilter', SubstringFilter()),
                        NamedType('greaterOrEqual', GreaterOrEqual()),
                        NamedType('lessOrEqual', LessOrEqual()),
                        NamedType('present', Present()),
                        NamedType('approxMatch', ApproxMatch()),
                        NamedType('extensibleMatch', ExtensibleMatch())
)


class PartialAttributeList(SequenceOf):
    # PartialAttributeList ::= SEQUENCE OF
    #     partialAttribute PartialAttribute
    components = PartialAttribute()


class Operation(Enumerated):
    # operation       ENUMERATED {
    #     add     (0),
    #     delete  (1),
    #     replace (2),
    #     ...  }
    valuemap = ValueMap(('add', 0), ('delete', 1), ('replace', 2), ('increment', 3))


class Change(Sequence):
    # change SEQUENCE {
    #     operation       ENUMERATED {
    #         add     (0),
    #         delete  (1),
    #         replace (2),
    #         ...  },
    #     modification    PartialAttribute } }
    namedValues = NamedValues(NamedType('operation', Operation()),
                               NamedType('modification', PartialAttribute()))


class Changes(SequenceOf):
    # changes         SEQUENCE OF change SEQUENCE
    components = Change()


class DeleteOldRDN(Boolean):
    # deleteoldrdn    BOOLEAN
    pass


class NewSuperior(LDAPDN):
    # newSuperior     [0] LDAPDN
    tag = Tag(tagClassContext, tagFormatSimple, 0)


class RequestName(LDAPOID):
    # requestName      [0] LDAPOID
    tag = Tag(tagClassContext, tagFormatSimple, 0)


class RequestValue(OctetString):
    # requestValue     [1] OCTET STRING
    tag = Tag(tagClassContext, tagFormatSimple, 1)


class ResponseName(LDAPOID):
    # responseName      [10] LDAPOID
    tag = Tag(tagClassContext, tagFormatSimple, 10)


class ResponseValue(OctetString):
    # responseValue     [11] OCTET STRING
    tag = Tag(tagClassContext, tagFormatSimple, 11)


class IntermediateResponseName(LDAPOID):
    # responseName      [0] LDAPOID
    tag = Tag(tagClassContext, tagFormatSimple, 0)


class IntermediateResponseValue(OctetString):
    # responseValue     [1] OCTET STRING
    tag = Tag(tagClassContext, tagFormatSimple, 1)



# LDAP Operations


class BindRequest(Sequence):
    # BindRequest ::= [APPLICATION 0] SEQUENCE {
    #     version                 INTEGER (1 ..  127),
    #     name                    LDAPDN,
    #     authentication          AuthenticationChoice }
    tag = Tag(tagClassApplication, tagFormatConstructed, 0)
    namedValues = NamedValues(NamedType('version', Version()),
                               NamedType('name', LDAPDN()),
                               NamedType('authentication', AuthenticationChoice()))


class BindResponse(Sequence):
    # BindResponse ::= [APPLICATION 1] SEQUENCE {
    #     COMPONENTS OF LDAPResult,
    #     serverSaslCreds    [7] OCTET STRING OPTIONAL }
    tag = Tag(tagClassApplication, tagFormatConstructed, 1)
    amedValues = NamedValues(NamedType('resultCode', ResultCode()),
                               NamedType('matchedDN', LDAPDN()),
                               NamedType('diagnosticMessage', LDAPString()),
                               OptionalNamedType('referral', Referral()),
                               OptionalNamedType('serverSaslCreds', ServerSaslCreds()))


class UnbindRequest(Null):
    # UnbindRequest ::= [APPLICATION 2] NULL
    tag = Tag(tagClassApplication, tagFormatSimple, 2)


class SearchRequest(Sequence):
    # SearchRequest ::= [APPLICATION 3] SEQUENCE {
    #     baseObject      LDAPDN,
    #     scope           ENUMERATED {
    #         baseObject              (0),
    #         singleLevel             (1),
    #         wholeSubtree            (2),
    #     ...  },
    #     derefAliases    ENUMERATED {
    #         neverDerefAliases       (0),
    #         derefInSearching        (1),
    #         derefFindingBaseObj     (2),
    #         derefAlways             (3) },
    #     sizeLimit       INTEGER (0 ..  maxInt),
    #     timeLimit       INTEGER (0 ..  maxInt),
    #     typesOnly       BOOLEAN,
    #     filter          Filter,
    #     attributes      AttributeSelection }
    tag = Tag(tagClassApplication, tagFormatConstructed, 3)
    namedValues = NamedValues(
        NamedType('baseObject', BaseObject()),
        NamedType('scope', Scope()),
        NamedType('derefAliases', DerefAliases()),
        NamedType('sizeLimit', SizeLimit()),
        NamedType('timeLimit', TimeLimit()),
        NamedType('typesOnly', TypesOnly()),
        NamedType('filter', Filter()),
        NamedType('attributes', AttributeSelection())
    )


class SearchResultReference(SequenceOf):
    # SearchResultReference ::= [APPLICATION 19] SEQUENCE
    #     SIZE (1..MAX) OF uri URI
    tag = Tag(tagClassApplication, tagFormatConstructed, 19)
    components= URI()


class SearchResultEntry(Sequence):
    # SearchResultEntry ::= [APPLICATION 4] SEQUENCE {
    #     objectName      LDAPDN,
    #     attributes      PartialAttributeList }
    tag = Tag(tagClassApplication, tagFormatConstructed, 4)
    namedValues = NamedValues(NamedType('object', LDAPDN()),
                               NamedType('attributes', PartialAttributeList()))


class SearchResultDone(LDAPResult):
    # SearchResultDone ::= [APPLICATION 5] LDAPResult
    tag = Tag(tagClassApplication, tagFormatConstructed, 5)


class ModifyRequest(Sequence):
    # ModifyRequest ::= [APPLICATION 6] SEQUENCE {
    #     object          LDAPDN,
    #     changes         SEQUENCE OF change SEQUENCE {
    #         operation       ENUMERATED {
    #             add     (0),
    #             delete  (1),
    #             replace (2),
    #             ...  },
    #         modification    PartialAttribute } }
    tag = Tag(tagClassApplication, tagFormatConstructed, 6)
    namedValues = NamedValues(NamedType('object', LDAPDN()),
                               NamedType('changes', Changes()))


class ModifyResponse(LDAPResult):
    # ModifyResponse ::= [APPLICATION 7] LDAPResult
    tag = Tag(tagClassApplication, tagFormatConstructed, 7)


class AddRequest(Sequence):
    # AddRequest ::= [APPLICATION 8] SEQUENCE {
    #     entry           LDAPDN,
    #     attributes      AttributeList }
    tag = Tag(tagClassApplication, tagFormatConstructed, 8)
    namedValues = NamedValues(NamedType('entry', LDAPDN()),
                               NamedType('attributes', AttributeList()))


class AddResponse(LDAPResult):
    # AddResponse ::= [APPLICATION 9] LDAPResult
    tag = Tag(tagClassApplication, tagFormatConstructed, 9)


class DelRequest(LDAPDN):
    # DelRequest ::= [APPLICATION 10] LDAPDN
    tag = Tag(tagClassApplication, tagFormatSimple, 10)


class DelResponse(LDAPResult):
    # DelResponse ::= [APPLICATION 11] LDAPResult
    tag = Tag(tagClassApplication, tagFormatConstructed, 11)


class ModifyDNRequest(Sequence):
    # ModifyDNRequest ::= [APPLICATION 12] SEQUENCE {
    #     entry           LDAPDN,
    #     newrdn          RelativeLDAPDN,
    #     deleteoldrdn    BOOLEAN,
    #     newSuperior     [0] LDAPDN OPTIONAL }
    tag = Tag(tagClassApplication, tagFormatConstructed, 12)
    namedValues = NamedValues(NamedType('entry', LDAPDN()),
                               NamedType('newrdn', RelativeLDAPDN()),
                               NamedType('deleteoldrdn', DeleteOldRDN()),
                               OptionalNamedType('newSuperior', NewSuperior()))


class ModifyDNResponse(LDAPResult):
    # ModifyDNResponse ::= [APPLICATION 13] LDAPResult
    tag = Tag(tagClassApplication, tagFormatConstructed, 13)


class CompareRequest(Sequence):
    # CompareRequest ::= [APPLICATION 14] SEQUENCE {
    #     entry           LDAPDN,
    #     ava             AttributeValueAssertion }
    tag = Tag(tagClassApplication, tagFormatConstructed, 14)
    namedValues = NamedValues(NamedType('entry', LDAPDN()),
                               NamedType('ava', AttributeValueAssertion()))


class CompareResponse(LDAPResult):
    # CompareResponse ::= [APPLICATION 15] LDAPResult
    tag = Tag(tagClassApplication, tagFormatConstructed, 15)



class AbandonRequest(MessageID):
    # AbandonRequest ::= [APPLICATION 16] MessageID
    tag = Tag(tagClassApplication, tagFormatSimple, 16)


class ExtendedRequest(Sequence):
    # ExtendedRequest ::= [APPLICATION 23] SEQUENCE {
    #     requestName      [0] LDAPOID,
    #     requestValue     [1] OCTET STRING OPTIONAL }
    tag = Tag(tagClassApplication, tagFormatConstructed, 23)
    namedValues = NamedValues(NamedType('requestName', RequestName()),
                               OptionalNamedType('requestValue', RequestValue()))


class ExtendedResponse(Sequence):
    # ExtendedResponse ::= [APPLICATION 24] SEQUENCE {
    #     COMPONENTS OF LDAPResult,
    #     responseName     [10] LDAPOID OPTIONAL,
    #     responseValue    [11] OCTET STRING OPTIONAL }
    tag = Tag(tagClassApplication, tagFormatConstructed, 24)
    namedValues = NamedValues(NamedType('resultCode', ResultCode()),
                               NamedType('matchedDN', LDAPDN()),
                               NamedType('diagnosticMessage', LDAPString()),
                               OptionalNamedType('referral', Referral()),
                               OptionalNamedType('responseName', ResponseName()),
                               OptionalNamedType('responseValue', ResponseValue()))


class IntermediateResponse(Sequence):
    # IntermediateResponse ::= [APPLICATION 25] SEQUENCE {
    #     responseName     [0] LDAPOID OPTIONAL,
    #     responseValue    [1] OCTET STRING OPTIONAL }
    tag = Tag(tagClassApplication, tagFormatConstructed, 25)
    namedValues = NamedValues(OptionalNamedType('responseName', IntermediateResponseName()),
                               OptionalNamedType('responseValue', IntermediateResponseValue()))


# LDAP Mesage

class ProtocolOp(Choice):
    # protocolOp      CHOICE {
    #     bindRequest           BindRequest,
    #     bindResponse          BindResponse,
    #     unbindRequest         UnbindRequest,
    #     searchRequest         SearchRequest,
    #     searchResEntry        SearchResultEntry,
    #     searchResDone         SearchResultDone,
    #     searchResRef          SearchResultReference,
    #     modifyRequest         ModifyRequest,
    #     modifyResponse        ModifyResponse,
    #     addRequest            AddRequest,
    #     addResponse           AddResponse,
    #     delRequest            DelRequest,
    #     delResponse           DelResponse,
    #     modDNRequest          ModifyDNRequest,
    #     modDNResponse         ModifyDNResponse,
    #     compareRequest        CompareRequest,
    #     compareResponse       CompareResponse,
    #     abandonRequest        AbandonRequest,
    #     extendedReq           ExtendedRequest,
    #     extendedResp          ExtendedResponse,
    #     ...,
    #     intermediateResponse  IntermediateResponse }
    namedValues = NamedValues(NamedType('bindRequest', BindRequest()),
                               NamedType('bindResponse', BindResponse()),
                               NamedType('unbindRequest', UnbindRequest()),
                               NamedType('searchRequest', SearchRequest()),
                               NamedType('searchResEntry', SearchResultEntry()),
                               NamedType('searchResDone', SearchResultDone()),
                               NamedType('searchResRef', SearchResultReference()),
                               NamedType('modifyRequest', ModifyRequest()),
                               NamedType('modifyResponse', ModifyResponse()),
                               NamedType('addRequest', AddRequest()),
                               NamedType('addResponse', AddResponse()),
                               NamedType('delRequest', DelRequest()),
                               NamedType('delResponse', DelResponse()),
                               NamedType('modDNRequest', ModifyDNRequest()),
                               NamedType('modDNResponse', ModifyDNResponse()),
                               NamedType('compareRequest', CompareRequest()),
                               NamedType('compareResponse', CompareResponse()),
                               NamedType('abandonRequest', AbandonRequest()),
                               NamedType('extendedReq', ExtendedRequest()),
                               NamedType('extendedResp', ExtendedResponse()),
                               NamedType('intermediateResponse', IntermediateResponse()))


class LDAPMessage(Sequence):
    # LDAPMessage ::= SEQUENCE {
    #     messageID       MessageID,
    #     protocolOp      CHOICE {
    #         bindRequest           BindRequest,
    #         bindResponse          BindResponse,
    #         unbindRequest         UnbindRequest,
    #         searchRequest         SearchRequest,
    #         searchResEntry        SearchResultEntry,
    #         searchResDone         SearchResultDone,
    #         searchResRef          SearchResultReference,
    #         modifyRequest         ModifyRequest,
    #         modifyResponse        ModifyResponse,
    #         addRequest            AddRequest,
    #         addResponse           AddResponse,
    #         delRequest            DelRequest,
    #         delResponse           DelResponse,
    #         modDNRequest          ModifyDNRequest,
    #         modDNResponse         ModifyDNResponse,
    #         compareRequest        CompareRequest,
    #         compareResponse       CompareResponse,
    #         abandonRequest        AbandonRequest,
    #         extendedReq           ExtendedRequest,
    #         extendedResp          ExtendedResponse,
    #         ...,
    #         intermediateResponse  IntermediateResponse },
    #     controls       [0] Controls OPTIONAL }
    namedValues = NamedValues(NamedType('messageID', MessageID()),
                               NamedType('protocolOp', ProtocolOp()),
                               OptionalNamedType('controls', Controls()))
