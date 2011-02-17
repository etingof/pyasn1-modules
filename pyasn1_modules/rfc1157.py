#
# SNMP message syntax
#
# ASN.1 source from:
# http://www.trl.ibm.com/projects/xml/xss4j/data/asn1/grammars/snmp.asn
#
# Sample captures from:
# http://wiki.wireshark.org/SampleCaptures/
#
from pyasn1.type import univ, namedtype, namedval, tag, constraint

class Version(univ.Integer):
    namedValues = namedval.NamedValues(
        ('version-1', 0)
        )
    defaultValue = 0

class Community(univ.OctetString): pass

class RequestID(univ.Integer): pass
class ErrorStatus(univ.Integer):
    namedValues = namedval.NamedValues(
        ('noError', 0),
        ('tooBig', 1),
        ('noSuchName', 2),
        ('badValue', 3),
        ('readOnly', 4),
        ('genErr', 5)
        )
class ErrorIndex(univ.Integer): pass

class ObjectName(univ.ObjectIdentifier): pass

class SimpleSyntax(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('number', univ.Integer()),
        namedtype.NamedType('string', univ.OctetString()),
        namedtype.NamedType('object', univ.ObjectIdentifier()),
        namedtype.NamedType('empty', univ.Null())
        )

class IpAddress(univ.OctetString):
    tagSet = univ.OctetString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 0)
        )
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueSizeConstraint(
        4, 4
        )
class NetworkAddress(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('internet', IpAddress())
        )

class Counter(univ.Integer):
    tagSet = univ.Integer.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 1)
        )
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(
        0, 4294967295L
        )
class Gauge(univ.Integer):
    tagSet = univ.Integer.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 2)
        )
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(
        0, 4294967295L
        )
class TimeTicks(univ.Integer):
    tagSet = univ.Integer.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 3)
        )
    subtypeSpec = univ.Integer.subtypeSpec + constraint.ValueRangeConstraint(
        0, 4294967295L
        )
class Opaque(univ.OctetString):
    tagSet = univ.OctetString.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassApplication, tag.tagFormatSimple, 4)
        )
    
class ApplicationSyntax(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('address', NetworkAddress()),
        namedtype.NamedType('counter', Counter()),
        namedtype.NamedType('gauge', Gauge()),
        namedtype.NamedType('ticks', TimeTicks()),
        namedtype.NamedType('arbitrary', Opaque())
        )
    
class ObjectSyntax(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('simple', SimpleSyntax()),
        namedtype.NamedType('application-wide', ApplicationSyntax())
        )
    
class VarBind(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('name', ObjectName()),
        namedtype.NamedType('value', ObjectSyntax())
        )
class VarBindList(univ.SequenceOf):
    componentType = VarBind()

class _RequestBase(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('request-id', RequestID()),
        namedtype.NamedType('error-status', ErrorStatus()),
        namedtype.NamedType('error-index', ErrorIndex()),
        namedtype.NamedType('variable-bindings', VarBindList())
        )
                            
class GetRequestPDU(_RequestBase):
    tagSet = _RequestBase.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 0)
        )    
class GetNextRequestPDU(_RequestBase):
    tagSet = _RequestBase.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 1)
        )
class GetResponsePDU(_RequestBase):
    tagSet = _RequestBase.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 2)
        )
class SetRequestPDU(_RequestBase):
    tagSet = _RequestBase.tagSet.tagImplicitly(
        tag.Tag(tag.tagClassContext, tag.tagFormatConstructed, 3)
        )

class TrapPDU(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('enterprise', univ.ObjectIdentifier()),
        namedtype.NamedType('agent-addr', NetworkAddress()),
        namedtype.NamedType('generic-trap', univ.Integer().clone(namedValues=namedval.NamedValues(('coldStart', 0), ('warmStart', 1), ('linkDown', 2), ('linkUp', 3), ('authenticationFailure', 4), ('egpNeighborLoss', 5), ('enterpriseSpecific', 6)))),
        namedtype.NamedType('specific-trap', univ.Integer()),
        namedtype.NamedType('time-stamp', TimeTicks()),
        namedtype.NamedType('variable-bindings', VarBindList())
        )
    
class Pdus(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('get-request', GetRequestPDU()),
        namedtype.NamedType('get-next-request', GetNextRequestPDU()),
        namedtype.NamedType('get-response', GetResponsePDU()),
        namedtype.NamedType('set-request', SetRequestPDU()),
        namedtype.NamedType('trap', TrapPDU())
        )
        
class Message(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', Version()),
        namedtype.NamedType('community', Community()),
        namedtype.NamedType('data', Pdus())
        )
