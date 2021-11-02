# This file is being contributed to pyasn1-modules software.
#
# Created by Hisanobu Okuda with assistance from asn1ate v.0.6.0.
#
# Copyright (c) 2021, Hisanobu Okuda <hisanobu.okuda@gmail.com>
# License: http://snmplabs.com/pyasn1/license.html
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc4511.txt


from pyasn1.type import univ, char, namedtype, namedval, tag, constraint


maxInt = univ.Integer(2147483647)
MAX = float('inf')


class MessageID(univ.Integer):
    pass


MessageID.subtypeSpec = constraint.ValueRangeConstraint(0, maxInt)


class AbandonRequest(MessageID):
    pass


AbandonRequest.tagSet = MessageID.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 16))


class AttributeValue(univ.OctetString):
    pass


class LDAPString(univ.OctetString):
    pass


class AttributeDescription(LDAPString):
    pass


class PartialAttribute(univ.Sequence):
    pass


PartialAttribute.componentType = namedtype.NamedTypes(
    namedtype.NamedType('type', AttributeDescription()),
    namedtype.NamedType('vals', univ.SetOf(componentType=AttributeValue())))


class Attribute(PartialAttribute):
    pass


class AttributeList(univ.SequenceOf):
    pass


AttributeList.componentType = Attribute()


class LDAPDN(LDAPString):
    pass


class AddRequest(univ.Sequence):
    pass


AddRequest.tagSet = univ.Sequence.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 8))
AddRequest.componentType = namedtype.NamedTypes(
    namedtype.NamedType('entry', LDAPDN()),
    namedtype.NamedType('attributes', AttributeList()))


class URI(LDAPString):
    pass


class Referral(univ.SequenceOf):
    pass


Referral.componentType = URI()
Referral.subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class LDAPResult(univ.Sequence):
    pass


LDAPResult.componentType = namedtype.NamedTypes(
    namedtype.NamedType('resultCode', univ.Enumerated(namedValues=namedval.NamedValues(
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
    namedtype.OptionalNamedType('referral', Referral().subtype(
            implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))))


class AddResponse(LDAPResult):
    pass


AddResponse.tagSet = LDAPResult.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 9))


class AssertionValue(univ.OctetString):
    pass


class AttributeSelection(univ.SequenceOf):
    class Selector(univ.Sequence):
        pass


AttributeSelection.componentType = LDAPString()


class AttributeValueAssertion(univ.Sequence):
    pass


AttributeValueAssertion.componentType = namedtype.NamedTypes(
    namedtype.NamedType('attributeDesc', AttributeDescription()),
    namedtype.NamedType('assertionValue', AssertionValue()))


class SaslCredentials(univ.Sequence):
    pass


SaslCredentials.componentType = namedtype.NamedTypes(
    namedtype.NamedType('mechanism', LDAPString()),
    namedtype.OptionalNamedType('credentials', univ.OctetString()))


class AuthenticationChoice(univ.Choice):
    pass


AuthenticationChoice.componentType = namedtype.NamedTypes(
    namedtype.NamedType('simple', univ.OctetString().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
    namedtype.NamedType('sasl', SaslCredentials().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))))


class BindRequest(univ.Sequence):
    pass


BindRequest.tagSet = univ.Sequence.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 0))
BindRequest.componentType = namedtype.NamedTypes(
    namedtype.NamedType('version', univ.Integer().subtype(
        subtypeSpec=constraint.ValueRangeConstraint(1, 127))),
    namedtype.NamedType('name', LDAPDN()),
    namedtype.NamedType('authentication', AuthenticationChoice()))


class BindResponse(univ.Sequence):
    pass


BindResponse.tagSet = univ.Sequence.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 1))
BindResponse.componentType = namedtype.NamedTypes(
    namedtype.NamedType('resultCode', univ.Enumerated(namedValues=namedval.NamedValues(
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
    namedtype.OptionalNamedType('referral', Referral().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
    namedtype.OptionalNamedType('serverSaslCreds', univ.OctetString().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))))


class CompareRequest(univ.Sequence):
    pass


CompareRequest.tagSet = univ.Sequence.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 14))
CompareRequest.componentType = namedtype.NamedTypes(
    namedtype.NamedType('entry', LDAPDN()),
    namedtype.NamedType('ava', AttributeValueAssertion()))


class CompareResponse(LDAPResult):
    pass


CompareResponse.tagSet = LDAPResult.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 15))


class LDAPOID(univ.OctetString):
    pass


class Control(univ.Sequence):
    pass


Control.componentType = namedtype.NamedTypes(
    namedtype.NamedType('controlType', LDAPOID()),
    namedtype.DefaultedNamedType('criticality', univ.Boolean().subtype(value=0)),
    namedtype.OptionalNamedType('controlValue', univ.OctetString()))


class Controls(univ.SequenceOf):
    pass


Controls.componentType = Control()


class DelRequest(LDAPDN):
    pass


DelRequest.tagSet = LDAPDN.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 10))


class DelResponse(LDAPResult):
    pass


DelResponse.tagSet = LDAPResult.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 11))


class ExtendedRequest(univ.Sequence):
    pass


ExtendedRequest.tagSet = univ.Sequence.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 23))
ExtendedRequest.componentType = namedtype.NamedTypes(
    namedtype.NamedType('requestName', LDAPOID().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
    namedtype.OptionalNamedType('requestValue', univ.OctetString().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))))


class ExtendedResponse(univ.Sequence):
    pass


ExtendedResponse.tagSet = univ.Sequence.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 24))
ExtendedResponse.componentType = namedtype.NamedTypes(
    namedtype.NamedType('resultCode', univ.Enumerated(namedValues=namedval.NamedValues(
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
    namedtype.OptionalNamedType('referral', Referral().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
    namedtype.OptionalNamedType('responseName', LDAPOID().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 10))),
    namedtype.OptionalNamedType('responseValue', univ.OctetString().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 11)))
)


class MatchingRuleId(LDAPString):
    pass


class MatchingRuleAssertion(univ.Sequence):
    pass


MatchingRuleAssertion.componentType = namedtype.NamedTypes(
    namedtype.OptionalNamedType('matchingRule', MatchingRuleId().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
    namedtype.OptionalNamedType('type', AttributeDescription().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2))),
    namedtype.NamedType('matchValue', AssertionValue().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 3))),
    namedtype.DefaultedNamedType('dnAttributes', univ.Boolean().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 4)).subtype(value=0))
)


class SubstringFilter(univ.Sequence):
    pass


SubstringFilter.componentType = namedtype.NamedTypes(
    namedtype.NamedType('type', AttributeDescription()),
    namedtype.NamedType('substrings', univ.SequenceOf(
        componentType=univ.Choice(componentType=namedtype.NamedTypes(
            namedtype.NamedType('initial', AssertionValue().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
            namedtype.NamedType('any', AssertionValue().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
            namedtype.NamedType('final', AssertionValue().subtype(
                implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 2)))))).subtype(
                    subtypeSpec=constraint.ValueSizeConstraint(1, MAX))))


# Tricky hack to handle recursive filter definitions:
class MetaFilter(type):
    _recursion = 0
    _max_recursion = 4  # up to 5 levels

    def __new__(self, name, bases, dictionary):
        return MetaFilter.get_class()

    @classmethod
    def get_class(cls):
        recursion = cls._recursion
        cls_name = "Filter" + str(recursion)
        cls._recursion += 1

        if recursion < cls._max_recursion:
            sub_filter_class = MetaFilter.get_class()
            cls = type(cls_name, (univ.Choice,), {
                "componentType": namedtype.NamedTypes(
                    namedtype.NamedType('and', univ.SetOf(componentType=sub_filter_class()).subtype(
                        subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
                    ).subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
                    namedtype.NamedType('or', univ.SetOf(componentType=sub_filter_class()).subtype(
                        subtypeSpec=constraint.ValueSizeConstraint(1, MAX)
                    ).subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))),
                    namedtype.NamedType('not', sub_filter_class().subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2))),
                    namedtype.NamedType('equalityMatch', AttributeValueAssertion().subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))),
                    namedtype.NamedType('substrings', SubstringFilter().subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4))),
                    namedtype.NamedType('greaterOrEqual', AttributeValueAssertion().subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 5))),
                    namedtype.NamedType('lessOrEqual', AttributeValueAssertion().subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 6))),
                    namedtype.NamedType('present', AttributeDescription().subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
                    namedtype.NamedType('approxMatch', AttributeValueAssertion().subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 8))),
                    namedtype.NamedType('extensibleMatch', MatchingRuleAssertion().subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 9)))
                ),
            })
        else:
            cls = type(cls_name + "last", (univ.Choice,), {
                "componentType": namedtype.NamedTypes(
                    namedtype.NamedType('equalityMatch', AttributeValueAssertion().subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3))),
                    namedtype.NamedType('substrings', SubstringFilter().subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 4))),
                    namedtype.NamedType('greaterOrEqual', AttributeValueAssertion().subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 5))),
                    namedtype.NamedType('lessOrEqual', AttributeValueAssertion().subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 6))),
                    namedtype.NamedType('present', AttributeDescription().subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 7))),
                    namedtype.NamedType('approxMatch', AttributeValueAssertion().subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 8))),
                    namedtype.NamedType('extensibleMatch', MatchingRuleAssertion().subtype(
                        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 9)))
                ),
            })
        return cls


# Tricky hack to support both of python2 and 3
FilterBase = MetaFilter("Filter", (object, ), {"__doc__": MetaFilter.__doc__})


class Filter(FilterBase):
    pass


class IntermediateResponse(univ.Sequence):
    pass


IntermediateResponse.tagSet = univ.Sequence.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 25))
IntermediateResponse.componentType = namedtype.NamedTypes(
    namedtype.OptionalNamedType('responseName', LDAPOID().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))),
    namedtype.OptionalNamedType('responseValue', univ.OctetString().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 1))))


class SearchRequest(univ.Sequence):
    pass


SearchRequest.tagSet = univ.Sequence.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 3))
SearchRequest.componentType = namedtype.NamedTypes(
    namedtype.NamedType('baseObject', LDAPDN()),
    namedtype.NamedType('scope', univ.Enumerated(namedValues=namedval.NamedValues(
        ('baseObject', 0),
        ('singleLevel', 1),
        ('wholeSubtree', 2)))),
    namedtype.NamedType('derefAliases', univ.Enumerated(namedValues=namedval.NamedValues(
        ('neverDerefAliases', 0),
        ('derefInSearching', 1),
        ('derefFindingBaseObj', 2),
        ('derefAlways', 3)))),
    namedtype.NamedType('sizeLimit', univ.Integer().subtype(
        subtypeSpec=constraint.ValueRangeConstraint(0, maxInt))),
    namedtype.NamedType('timeLimit', univ.Integer().subtype(
        subtypeSpec=constraint.ValueRangeConstraint(0, maxInt))),
    namedtype.NamedType('typesOnly', univ.Boolean()),
    namedtype.NamedType('filter', Filter()),
    namedtype.NamedType('attributes', AttributeSelection()))


class RelativeLDAPDN(LDAPString):
    pass


class ModifyDNRequest(univ.Sequence):
    pass


ModifyDNRequest.tagSet = univ.Sequence.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 12))
ModifyDNRequest.componentType = namedtype.NamedTypes(
    namedtype.NamedType('entry', LDAPDN()),
    namedtype.NamedType('newrdn', RelativeLDAPDN()),
    namedtype.NamedType('deleteoldrdn', univ.Boolean()),
    namedtype.OptionalNamedType('newSuperior', LDAPDN().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))))


class PartialAttributeList(univ.SequenceOf):
    pass


PartialAttributeList.componentType = PartialAttribute()


class SearchResultEntry(univ.Sequence):
    pass


SearchResultEntry.tagSet = univ.Sequence.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 4))
SearchResultEntry.componentType = namedtype.NamedTypes(
    namedtype.NamedType('objectName', LDAPDN()),
    namedtype.NamedType('attributes', PartialAttributeList()))


class ModifyDNResponse(LDAPResult):
    pass


ModifyDNResponse.tagSet = LDAPResult.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 13))


class SearchResultReference(univ.SequenceOf):
    pass


SearchResultReference.tagSet = univ.SequenceOf.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 19))
SearchResultReference.componentType = URI()
SearchResultReference.subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class SearchResultDone(LDAPResult):
    pass


SearchResultDone.tagSet = LDAPResult.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 5))


class ModifyResponse(LDAPResult):
    pass


ModifyResponse.tagSet = LDAPResult.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 7))


class ModifyRequest(univ.Sequence):
    pass


ModifyRequest.tagSet = univ.Sequence.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatConstructed, 6))
ModifyRequest.componentType = namedtype.NamedTypes(
    namedtype.NamedType('object', LDAPDN()),
    namedtype.NamedType('changes', univ.SequenceOf(componentType=univ.Sequence(
        componentType=namedtype.NamedTypes(
            namedtype.NamedType('operation', univ.Enumerated(namedValues=namedval.NamedValues(
                ('add', 0),
                ('delete', 1),
                ('replace', 2)))),
            namedtype.NamedType('modification', PartialAttribute()))))))


class UnbindRequest(univ.Null):
    pass


UnbindRequest.tagSet = univ.Null.tagSet.tagImplicitly(
    tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 2))


class LDAPMessage(univ.Sequence):
    pass


LDAPMessage.componentType = namedtype.NamedTypes(
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
        namedtype.NamedType('intermediateResponse', IntermediateResponse())))),
    namedtype.OptionalNamedType('controls', Controls().subtype(
        implicitTag=tag.Tag(tag.tagClassContext, tag.tagFormatSimple, 0))))
