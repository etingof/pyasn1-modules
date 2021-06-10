#
# This file is part of pyasn1-alt-modules software.
#
# Created by Russ Housley with some help from asn1ate v.0.6.0
#
# Copyright (c) 2021, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#
# Server-Based Certificate Validation Protocol (SCVP)
#
# ASN.1 source from:
# https://www.rfc-editor.org/rfc/rfc5055.txt
# https://www.rfc-editor.org/rfc/rfc5912.txt
#

from pyasn1.type import char
from pyasn1.type import constraint
from pyasn1.type import namedtype
from pyasn1.type import namedval
from pyasn1.type import opentype
from pyasn1.type import tag
from pyasn1.type import useful
from pyasn1.type import univ

from pyasn1_alt_modules import rfc5280
from pyasn1_alt_modules import rfc5652
from pyasn1_alt_modules import rfc6960
from pyasn1_alt_modules import rfc3281

MAX = float('inf')

scvpValidationPolMap = { }

scvpValidationAlgMap = { }

scvpWantBackMap = { }


# Imports from RFC 5280

AlgorithmIdentifier = rfc5280.AlgorithmIdentifier

Attribute = rfc5280.Attribute

Certificate = rfc5280.Certificate

Extensions = rfc5280.Extensions

CertificateList = rfc5280.CertificateList

CertificateSerialNumber = rfc5280.CertificateSerialNumber

GeneralNames = rfc5280.GeneralNames

GeneralName = rfc5280.GeneralName

KeyUsage = rfc5280.KeyUsage

KeyPurposeId = rfc5280.KeyPurposeId

SubjectPublicKeyInfo = rfc5280.SubjectPublicKeyInfo


# Imports from RFC 3281

AttributeCertificate = rfc3281.AttributeCertificate


# Imports from RFC 6960

OCSPResponse = rfc6960.OCSPResponse


# Imports from RFC 5652

ContentInfo = rfc5652.ContentInfo


# Server-Based Certificate Validation Protocol

sha_1 = univ.ObjectIdentifier((1, 3, 14, 3, 2, 26))

algid_SHA1 = AlgorithmIdentifier()
algid_SHA1['algorithm'] = sha_1
algid_SHA1['parameters'] = "\x05\x00"


class SCVPIssuerSerial(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('issuer', GeneralNames()),
        namedtype.NamedType('serialNumber', CertificateSerialNumber())
    )


class SCVPCertID(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('certHash', univ.OctetString()),
        namedtype.NamedType('issuerSerial', SCVPIssuerSerial()),
        namedtype.DefaultedNamedType('hashAlgorithm', algid_SHA1)
    )


class ACReference(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('attrCert', AttributeCertificate().subtype(
            implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatSimple, 2))),
        namedtype.NamedType('acRef', SCVPCertID().subtype(
            implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatConstructed, 3)))
    )


class AuthPolicy(univ.ObjectIdentifier):
    pass


class ValidationPolRef(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('valPolId', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('valPolParams', univ.Any(),
            openType=opentype.OpenType('valPolId', scvpValidationPolMap))
    )


class PKCReference(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('cert', Certificate().subtype(
            implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatSimple, 0))),
        namedtype.NamedType('pkcRef', SCVPCertID().subtype(
            implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatConstructed, 1)))
    )


class TrustAnchors(univ.SequenceOf):
    componentType = PKCReference()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class ValidationAlg(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('valAlgId', univ.ObjectIdentifier()),
        namedtype.OptionalNamedType('parameters', univ.Any(),
            openType=opentype.OpenType('valPolId', scvpValidationAlgMap))
    )


class ValidationPolicy(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('validationPolRef', ValidationPolRef()),
        namedtype.OptionalNamedType('validationAlg',
            ValidationAlg().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('userPolicySet',
            univ.SequenceOf(componentType=univ.ObjectIdentifier()).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)).subtype(
                    implicitTag=tag.Tag(tag.tagClassContext,
                        tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType('inhibitPolicyMapping',
            univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType('requireExplicitPolicy',
            univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatSimple, 3))),
        namedtype.OptionalNamedType('inhibitAnyPolicy',
            univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatSimple, 4))),
        namedtype.OptionalNamedType('trustAnchors',
            TrustAnchors().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatSimple, 5))),
        namedtype.OptionalNamedType('keyUsages',
            univ.SequenceOf(componentType=KeyUsage()).subtype(
                implicitTag=tag.Tag(tag.tagClassContext,
                    tag.tagFormatSimple, 6))),
        namedtype.OptionalNamedType('extendedKeyUsages',
            univ.SequenceOf(componentType=KeyPurposeId()).subtype(
                implicitTag=tag.Tag(tag.tagClassContext,
                    tag.tagFormatSimple, 7))),
        namedtype.OptionalNamedType('specifiedKeyUsages',
            univ.SequenceOf(componentType=KeyPurposeId()).subtype(
                implicitTag=tag.Tag(tag.tagClassContext,
                    tag.tagFormatSimple, 8)))
    )


class CertChecks(univ.SequenceOf):
    componentType = univ.ObjectIdentifier()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class ResponseFlags(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('fullRequestInResponse',
            univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatSimple, 0)).subtype(value=0)),
        namedtype.DefaultedNamedType('responseValidationPolByRef',
            univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatSimple, 1)).subtype(value=1)),
        namedtype.DefaultedNamedType('protectResponse',
            univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatSimple, 2)).subtype(value=1)),
        namedtype.DefaultedNamedType('cachedResponse',
            univ.Boolean().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatSimple, 3)).subtype(value=1))
    )


class CertBundle(univ.SequenceOf):
    componentType = Certificate()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class OtherRevInfo(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('riType', univ.ObjectIdentifier()),
        namedtype.NamedType('riValue', univ.Any(),
            openType=opentype.OpenType('riType',
                rfc5652.otherRevInfoFormatMap))
    )


class RevocationInfo(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('crl', CertificateList().subtype(
            implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatSimple, 0))),
        namedtype.NamedType('delta-crl', CertificateList().subtype(
            implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatSimple, 1))),
        namedtype.NamedType('ocsp', OCSPResponse().subtype(
            implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatSimple, 2))),
        namedtype.NamedType('other', OtherRevInfo().subtype(
            implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatConstructed, 3)))
    )


class RevocationInfos(univ.SequenceOf):
    componentType = RevocationInfo()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class CertReferences(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pkcRefs', univ.SequenceOf(
            componentType=PKCReference()).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)).subtype(
                    implicitTag=tag.Tag(tag.tagClassContext,
                        tag.tagFormatSimple, 0))),
        namedtype.NamedType('acRefs', univ.SequenceOf(
            componentType=ACReference()).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)).subtype(
                    implicitTag=tag.Tag(tag.tagClassContext,
                        tag.tagFormatSimple, 1)))
    )


class WantBack(univ.SequenceOf):
    componentType = univ.ObjectIdentifier()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class Query(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('queriedCerts', CertReferences()),
        namedtype.NamedType('checks', CertChecks()),
        namedtype.OptionalNamedType('wantBack',
            WantBack().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatSimple, 1))),
        namedtype.NamedType('validationPolicy', ValidationPolicy()),
        namedtype.OptionalNamedType('responseFlags', ResponseFlags()),
        namedtype.OptionalNamedType('serverContextInfo',
            univ.OctetString().subtype(implicitTag=tag.Tag(
                 tag.tagClassContext, tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType('validationTime',
            useful.GeneralizedTime().subtype(implicitTag=tag.Tag(
                 tag.tagClassContext, tag.tagFormatSimple, 3))),
        namedtype.OptionalNamedType('intermediateCerts',
            CertBundle().subtype(implicitTag=tag.Tag(
                 tag.tagClassContext, tag.tagFormatSimple, 4))),
        namedtype.OptionalNamedType('revInfos',
            RevocationInfos().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 5))),
        namedtype.OptionalNamedType('producedAt',
            useful.GeneralizedTime().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 6))),
        namedtype.OptionalNamedType('queryExtensions',
            Extensions().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 7)))
    )



class CVRequest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('cvRequestVersion',
            univ.Integer().subtype(value=1)),
        namedtype.NamedType('query', Query()),
        namedtype.OptionalNamedType('requestorRef',
            GeneralNames().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('requestNonce',
            univ.OctetString().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType('requestorName',
            GeneralName().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType('responderName',
            GeneralName().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 3))),
        namedtype.OptionalNamedType('requestExtensions',
            Extensions().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 4))),
        namedtype.OptionalNamedType('signatureAlg',
            AlgorithmIdentifier().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 5))),
        namedtype.OptionalNamedType('hashAlg',
            univ.ObjectIdentifier().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 6))),
        namedtype.OptionalNamedType('requestorText',
            char.UTF8String().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, 256)).subtype(
                    implicitTag=tag.Tag(tag.tagClassContext,
                        tag.tagFormatSimple, 7)))
    )


class RespValidationPolicy(ValidationPolicy):
    pass


class CertReference(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('pkc', PKCReference()),
        namedtype.NamedType('ac', ACReference())
    )


class ReplyStatus(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('success', 0),
        ('malformedPKC', 1),
        ('malformedAC', 2),
        ('unavailableValidationTime', 3),
        ('referenceCertHashFail', 4),
        ('certPathConstructFail', 5),
        ('certPathNotValid', 6),
        ('certPathNotValidNow', 7),
        ('wantBackUnsatisfied', 8)
    )


class ReplyCheck(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('check', univ.ObjectIdentifier()),
        namedtype.DefaultedNamedType('status', univ.Integer().subtype(value=0))
    )


class ReplyChecks(univ.SequenceOf):
    componentType = ReplyCheck()


class ReplyWantBack(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('wb', univ.ObjectIdentifier()),
        namedtype.NamedType('value', univ.OctetString())
    )


class ReplyWantBacks(univ.SequenceOf):
    componentType = ReplyWantBack()


class CertReply(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('cert', CertReference()),
        namedtype.DefaultedNamedType('replyStatus',
            ReplyStatus().subtype(value='success')),
        namedtype.NamedType('replyValTime', useful.GeneralizedTime()),
        namedtype.NamedType('replyChecks', ReplyChecks()),
        namedtype.NamedType('replyWantBacks', ReplyWantBacks()),
        namedtype.OptionalNamedType('validationErrors',
            univ.SequenceOf(componentType=univ.ObjectIdentifier()).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX)).subtype(
                    implicitTag=tag.Tag(tag.tagClassContext,
                        tag.tagFormatSimple, 0))),
        namedtype.OptionalNamedType('nextUpdate',
            useful.GeneralizedTime().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 1))),
        namedtype.OptionalNamedType('certReplyExtensions',
            Extensions().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 2)))
    )


class ReplyObjects(univ.SequenceOf):
    componentType = CertReply()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class HashValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('algorithm', algid_SHA1),
        namedtype.NamedType('value', univ.OctetString())
    )


class RequestReference(univ.Choice):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('requestHash',
            HashValue().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatConstructed, 0))),
        namedtype.NamedType('fullRequest',
            CVRequest().subtype(implicitTag=tag.Tag(tag.tagClassContext,
                tag.tagFormatConstructed, 1)))
    )


class CVStatusCode(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('okay', 0),
        ('skipUnrecognizedItems', 1),
        ('tooBusy', 10),
        ('invalidRequest', 11),
        ('internalError', 12),
        ('badStructure', 20),
        ('unsupportedVersion', 21),
        ('abortUnrecognizedItems', 22),
        ('unrecognizedSigKey', 23),
        ('badSignatureOrMAC', 24),
        ('unableToDecode', 25),
        ('notAuthorized', 26),
        ('unsupportedChecks', 27),
        ('unsupportedWantBacks', 28),
        ('unsupportedSignatureOrMAC', 29),
        ('invalidSignatureOrMAC', 30),
        ('protectedResponseUnsupported', 31),
        ('unrecognizedResponderName', 32),
        ('relayingLoop', 40),
        ('unrecognizedValPol', 50),
        ('unrecognizedValAlg', 51),
        ('fullRequestInResponseUnsupported', 52),
        ('fullPolResponseUnsupported', 53),
        ('inhibitPolicyMappingUnsupported', 54),
        ('requireExplicitPolicyUnsupported', 55),
        ('inhibitAnyPolicyUnsupported', 56),
        ('validationTimeUnsupported', 57),
        ('unrecognizedCritQueryExt', 63),
        ('unrecognizedCritRequestExt', 64)
    )


class ResponseStatus(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('statusCode',
            CVStatusCode().subtype(value='okay')),
        namedtype.OptionalNamedType('errorMessage',
            char.UTF8String())
    )


class CVResponse(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('cvResponseVersion', univ.Integer()),
        namedtype.NamedType('serverConfigurationID', univ.Integer()),
        namedtype.NamedType('producedAt', useful.GeneralizedTime()),
        namedtype.NamedType('responseStatus', ResponseStatus()),
        namedtype.OptionalNamedType('respValidationPolicy',
            RespValidationPolicy().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 0))),
        namedtype.OptionalNamedType('requestRef',
            RequestReference().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatConstructed, 1))),
        namedtype.OptionalNamedType('requestorRef',
            GeneralNames().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 2))),
        namedtype.OptionalNamedType('requestorName',
            GeneralNames().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 3))),
        namedtype.OptionalNamedType('replyObjects',
            ReplyObjects().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 4))),
        namedtype.OptionalNamedType('respNonce',
            univ.OctetString().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 5))),
        namedtype.OptionalNamedType('serverContextInfo',
            univ.OctetString().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 6))),
        namedtype.OptionalNamedType('cvResponseExtensions',
            Extensions().subtype(implicitTag=tag.Tag(
                tag.tagClassContext, tag.tagFormatSimple, 7))),
        namedtype.OptionalNamedType('requestorText',
            char.UTF8String().subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, 256)).subtype(
                    implicitTag=tag.Tag(tag.tagClassContext,
                        tag.tagFormatSimple, 8)))
    )


class CertBundles(univ.SequenceOf):
    componentType = CertBundle()
    subtypeSpec = constraint.ValueSizeConstraint(1, MAX)


class KeyAgreePublicKey(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', AlgorithmIdentifier()),
        namedtype.NamedType('publicKey', univ.BitString()),
        namedtype.NamedType('macAlgorithm', AlgorithmIdentifier()),
        namedtype.OptionalNamedType('kDF', AlgorithmIdentifier())
    )


class NameValidationAlgParms(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('nameCompAlgId', univ.ObjectIdentifier()),
        namedtype.NamedType('validationNames', GeneralNames())
    )

class ResponseTypes(univ.Enumerated):
    namedValues = namedval.NamedValues(
        ('cached-only', 0),
        ('non-cached-only', 1),
        ('cached-and-non-cached', 2)
    )


class RevInfoWantBack(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('revocationInfo', RevocationInfos()),
        namedtype.OptionalNamedType('extraCerts', CertBundle())
    )


class RevocationInfoTypes(univ.BitString):
    namedValues = namedval.NamedValues(
        ('fullCRLs', 0),
        ('deltaCRLs', 1),
        ('indirectCRLs', 2),
        ('oCSPResponses', 3)
    )


class SCVPResponses(univ.SequenceOf):
    componentType = ContentInfo()


class ValPolRequest(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.DefaultedNamedType('vpRequestVersion',
            univ.Integer().subtype(value=1)),
        namedtype.NamedType('requestNonce', univ.OctetString())
    )


class ValPolResponse(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('vpResponseVersion', univ.Integer()),
        namedtype.NamedType('maxCVRequestVersion', univ.Integer()),
        namedtype.NamedType('maxVPRequestVersion', univ.Integer()),
        namedtype.NamedType('serverConfigurationID', univ.Integer()),
        namedtype.NamedType('thisUpdate', useful.GeneralizedTime()),
        namedtype.OptionalNamedType('nextUpdate', useful.GeneralizedTime()),
        namedtype.NamedType('supportedChecks', CertChecks()),
        namedtype.NamedType('supportedWantBacks', WantBack()),
        namedtype.NamedType('validationPolicies',
            univ.SequenceOf(componentType=univ.ObjectIdentifier())),
        namedtype.NamedType('validationAlgs',
            univ.SequenceOf(componentType=univ.ObjectIdentifier())),
        namedtype.NamedType('authPolicies',
            univ.SequenceOf(componentType=AuthPolicy())),
        namedtype.NamedType('responseTypes', ResponseTypes()),
        namedtype.NamedType('defaultPolicyValues', RespValidationPolicy()),
        namedtype.NamedType('revocationInfoTypes', RevocationInfoTypes()),
        namedtype.NamedType('signatureGeneration',
            univ.SequenceOf(componentType=AlgorithmIdentifier())),
        namedtype.NamedType('signatureVerification',
            univ.SequenceOf(componentType=AlgorithmIdentifier())),
        namedtype.NamedType('hashAlgorithms',
            univ.SequenceOf(componentType=univ.ObjectIdentifier()).subtype(
                subtypeSpec=constraint.ValueSizeConstraint(1, MAX))),
        namedtype.OptionalNamedType('serverPublicKeys',
            univ.SequenceOf(componentType=KeyAgreePublicKey())),
        namedtype.DefaultedNamedType('clockSkew',
            univ.Integer().subtype(value=10)),
        namedtype.OptionalNamedType('requestNonce', univ.OctetString())
    )


# SCVP Check Identifiers

id_stc = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 7, 17))

id_stc_build_pkc_path = id_stc + (1,)

id_stc_build_valid_pkc_path = id_stc + (2,)

id_stc_build_status_checked_pkc_path = id_stc + (3,)

id_stc_build_aa_path = id_stc + (4,)

id_stc_build_valid_aa_path = id_stc + (5,)

id_stc_build_status_checked_aa_path = id_stc + (6,)

id_stc_status_check_ac_and_build_status_checked_aa_path = id_stc + (7,)


# SCVP WantBack Identifiers

id_swb = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 7, 18))

id_swb_pkc_best_cert_path = id_swb + (1,)

id_swb_pkc_revocation_info = id_swb + (2,)

id_swb_pkc_public_key_info = id_swb + (4,)

id_swb_aa_cert_path = id_swb + (5,)

id_swb_aa_revocation_info = id_swb + (6,)

id_swb_ac_revocation_info = id_swb + (7,)

id_swb_relayed_responses = id_swb + (9,)

id_swb_pkc_cert = id_swb + (10,)

id_swb_ac_cert = id_swb + (11,)

id_swb_pkc_all_cert_paths = id_swb + (12,)

id_swb_pkc_ee_revocation_info = id_swb + (13,)

id_swb_pkc_CAs_revocation_info = id_swb + (14,)


# SCVP Validation Policy and Algorithm Identifiers

id_svp = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 7, 19))

id_svp_defaultValPolicy = id_svp + (1,)

id_svp_nameValAlg = id_svp + (2,)

id_svp_basicValAlg = id_svp + (3,)

id_nva_dnCompAlg = id_svp + (4,)


# SCVP Basic Validation Algorithm Errors

id_bvae = univ.ObjectIdentifier(id_svp_basicValAlg)

id_bvae_expired = id_bvae + (1,)

id_bvae_not_yet_valid = id_bvae + (2,)

id_bvae_wrongTrustAnchor = id_bvae + (3,)

id_bvae_noValidCertPath = id_bvae + (4,)

id_bvae_revoked = id_bvae + (5,)

id_bvae_invalidKeyPurpose = id_bvae + (9,)

id_bvae_invalidKeyUsage = id_bvae + (10,)

id_bvae_invalidCertPolicy = id_bvae + (11,)


# SCVP Name Validation Algorithm Errors

id_nvae = univ.ObjectIdentifier(id_svp_nameValAlg)

id_nvae_name_mismatch = id_nvae + (1,)

id_nvae_no_name = id_nvae + (2,)

id_nvae_unknown_alg = id_nvae + (3,)

id_nvae_bad_name = id_nvae + (4,)

id_nvae_bad_name_type = id_nvae + (5,)

id_nvae_mixed_names = id_nvae + (6,)


# SCVP Extended Key Usage Key Purpose Identifiers

id_kp = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 7, 3))

id_kp_scvpServer = id_kp + (15,)

id_kp_scvpClient = id_kp + (16,)


# CMS Content Types

id_ct = univ.ObjectIdentifier((1, 2, 840, 113549, 1, 9, 16, 1))

id_ct_scvp_certValRequest = id_ct + (10,)

id_ct_scvp_certValResponse = id_ct + (11,)

id_ct_scvp_valPolRequest = id_ct + (12,)

id_ct_scvp_valPolResponse = id_ct + (13,)


# Update the Content Types map in rfc5652.py

_cmsContentTypesMapUpdate = {
    id_ct_scvp_certValRequest: CVRequest(),
    id_ct_scvp_certValResponse: CVResponse(),
    id_ct_scvp_valPolRequest: ValPolRequest(),
    id_ct_scvp_valPolResponse: ValPolResponse(),
}

rfc5652.cmsContentTypesMap.update(_cmsContentTypesMapUpdate)


# id_svp_defaultValPolicy: parameters MUST be absent
# so there is nothing to add to scvpValidationPolMap


# Update the SCVP Validation Algorithm map

_scvpValidationAlgMapUpdate = {
    # id_svp_basicValAlg: parameters MUST be absent
    id_svp_nameValAlg: NameValidationAlgParms(),
}

scvpValidationAlgMap.update(_scvpValidationAlgMapUpdate)


# Update the SCVP Want Back map

_scvpWantBackMapUpdate = {
    id_swb_pkc_best_cert_path: CertBundle(),
    id_swb_pkc_revocation_info: RevInfoWantBack(),
    id_swb_pkc_public_key_info: SubjectPublicKeyInfo(),
    id_swb_aa_cert_path: CertBundle(),
    id_swb_aa_revocation_info: RevInfoWantBack(),
    id_swb_ac_revocation_info: RevInfoWantBack(),
    id_swb_relayed_responses: SCVPResponses(),
    id_swb_pkc_cert: Certificate(),
    id_swb_ac_cert: AttributeCertificate(),
    id_swb_pkc_all_cert_paths: CertBundles(),
    id_swb_pkc_ee_revocation_info: RevInfoWantBack(),
    id_swb_pkc_CAs_revocation_info: RevInfoWantBack(),
}

scvpWantBackMap.update(_scvpWantBackMapUpdate)
