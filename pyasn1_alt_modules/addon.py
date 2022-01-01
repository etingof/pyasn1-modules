#
# This file is part of pyasn1-alt-modules software.
#
# This is for things that ought to be part of pyasn1, but contributions
# are no longer being merged and released.  Therefore, this module is
# used to make additions at runtime.
#
# Created by Russ Housley
# Copyright (c) 2021-2022, Vigil Security, LLC
# License: http://vigilsec.com/pyasn1-alt-modules-license.txt
#

from pyasn1.type import base
from pyasn1.type import constraint
from pyasn1.type import error
from pyasn1.type import tag

from pyasn1.codec.ber import encoder
from pyasn1.codec.ber import decoder

from pyasn1.compat.octets import isStringType, octs2ints


# ----------------------------------------------------------------------
#
# Implementation of the ASN.1 RELATIVE-OID typ1
#
# ----------------------------------------------------------------------


# ----------------------------------------------------------------------
# This would be better implemented in pyasn1.type.univ
# ----------------------------------------------------------------------

class RelativeOID(base.SimpleAsn1Type):
    """Create |ASN.1| schema or value object.

    |ASN.1| class is based on :class:`~pyasn1.type.base.SimpleAsn1Type`, its
    objects are immutable and duck-type Python :class:`tuple` objects
    (tuple of non-negative integers).

    Keyword Args
    ------------
    value: :class:`tuple`, :class:`str` or |ASN.1| object
        Python sequence of :class:`int` or :class:`str` literal or |ASN.1| object.
        If `value` is not given, schema object will be created.

    tagSet: :py:class:`~pyasn1.type.tag.TagSet`
        Object representing non-default ASN.1 tag(s)

    subtypeSpec: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection`
        Object representing non-default ASN.1 subtype constraint(s). Constraints
        verification for |ASN.1| type occurs automatically on object
        instantiation.

    Raises
    ------
    ~pyasn1.error.ValueConstraintError, ~pyasn1.error.PyAsn1Error
        On constraint violation or bad initializer.

    Examples
    --------
    .. code-block:: python

        class RelOID(RelativeOID):
            '''
            ASN.1 specification:

            id-pad-null RELATIVE-OID ::= { 0 }
            id-pad-once RELATIVE-OID ::= { 5 6 }
            id-pad-twice RELATIVE-OID ::= { 5 6 7 }
            '''
        id_pad_null = RelOID('0')
        id_pad_once = RelOID('5.6')
        id_pad_twice = id_pad_once + (7,)
    """
    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.tag.TagSet` object representing ASN.1 tag(s)
    #: associated with |ASN.1| type.
    tagSet = tag.initTagSet(
        tag.Tag(tag.tagClassUniversal, tag.tagFormatSimple, 0x0d)
    )

    #: Set (on class, not on instance) or return a
    #: :py:class:`~pyasn1.type.constraint.ConstraintsIntersection` object
    #: imposing constraints on |ASN.1| type initialization values.
    subtypeSpec = constraint.ConstraintsIntersection()

    # Optimization for faster codec lookup
    typeId = base.SimpleAsn1Type.getTypeId()

    def __add__(self, other):
        return self.clone(self._value + other)

    def __radd__(self, other):
        return self.clone(other + self._value)

    def asTuple(self):
        return self._value

    # Sequence object protocol

    def __len__(self):
        return len(self._value)

    def __getitem__(self, i):
        if i.__class__ is slice:
            return self.clone(self._value[i])
        else:
            return self._value[i]

    def __iter__(self):
        return iter(self._value)

    def __contains__(self, value):
        return value in self._value

    def index(self, suboid):
        return self._value.index(suboid)

    def isPrefixOf(self, other):
        """Indicate if this |ASN.1| object is a prefix of other |ASN.1| object.

        Parameters
        ----------
        other: |ASN.1| object
            |ASN.1| object

        Returns
        -------
        : :class:`bool`
            :obj:`True` if this |ASN.1| object is a parent (e.g. prefix) of the other |ASN.1| object
            or :obj:`False` otherwise.
        """
        l = len(self)
        if l <= len(other):
            if self._value[:l] == other[:l]:
                return True
        return False

    def prettyIn(self, value):
        if isinstance(value, RelativeOID):
            return tuple(value)
        elif isStringType(value):
            if '-' in value:
                raise error.PyAsn1Error(
                    'Malformed RELATIVE-OID %s at %s: %s' % (value, self.__class__.__name__, sys.exc_info()[1])
                )
            try:
                return tuple([int(subOid) for subOid in value.split('.') if subOid])
            except ValueError:
                raise error.PyAsn1Error(
                    'Malformed RELATIVE-OID %s at %s: %s' % (value, self.__class__.__name__, sys.exc_info()[1])
                )

        try:
            tupleOfInts = tuple([int(subOid) for subOid in value if subOid >= 0])

        except (ValueError, TypeError):
            raise error.PyAsn1Error(
                'Malformed RELATIVE-OID %s at %s: %s' % (value, self.__class__.__name__, sys.exc_info()[1])
            )

        if len(tupleOfInts) == len(value):
            return tupleOfInts

        raise error.PyAsn1Error('Malformed RELATIVE-OID %s at %s' % (value, self.__class__.__name__))

    def prettyOut(self, value):
        return '.'.join([str(x) for x in value])


# ----------------------------------------------------------------------
# This would be better implemented in pyasn1.type.codec.ber.encoder
# ----------------------------------------------------------------------

class RelativeOIDEncoder(encoder.AbstractItemEncoder):
    supportIndefLenMode = False

    def encodeValue(self, value, asn1Spec, encodeFun, **options):
        if asn1Spec is not None:
            value = asn1Spec.clone(value)

        octets = ()

        # Cycle through subIds
        for subOid in value.asTuple():
            if 0 <= subOid <= 127:
                # Optimize for the common case
                octets += (subOid,)

            elif subOid > 127:
                # Pack large Sub-Object IDs
                res = (subOid & 0x7f,)
                subOid >>= 7

                while subOid:
                    res = (0x80 | (subOid & 0x7f),) + res
                    subOid >>= 7

                # Add packed Sub-Object ID to resulted RELATIVE-OID
                octets += res

            else:
                raise error.PyAsn1Error('Negative RELATIVE-OID arc %s at %s' % (subOid, value))

        return octets, False, False



# ----------------------------------------------------------------------
# Additions to the TAG_MAP and TYPE_MAP in pyasn1.type.codec.ber.encoder
# ----------------------------------------------------------------------

if RelativeOID.tagSet not in encoder.TAG_MAP:
    encoder.TAG_MAP.update(
        { RelativeOID.tagSet: RelativeOIDEncoder(), } )

if RelativeOID.typeId not in encoder.TYPE_MAP:
    encoder.TYPE_MAP.update(
        { RelativeOID.typeId: RelativeOIDEncoder(), } )


# ----------------------------------------------------------------------
# This would be better implemented in pyasn1.type.codec.ber.decoder
# ----------------------------------------------------------------------

class RelativeOIDPayloadDecoder(decoder.AbstractSimplePayloadDecoder):
    protoComponent = RelativeOID(())

    def valueDecoder(self, substrate, asn1Spec,
                     tagSet=None, length=None, state=None,
                     decodeFun=None, substrateFun=None,
                     **options):
        if tagSet[0].tagFormat != tag.tagFormatSimple:
            raise error.PyAsn1Error('Simple tag format expected')

        for chunk in readFromStream(substrate, length, options):
            if isinstance(chunk, SubstrateUnderrunError):
                yield chunk

        if not chunk:
            raise error.PyAsn1Error('Empty substrate')

        chunk = octs2ints(chunk)

        reloid = ()
        index = 0
        substrateLen = len(chunk)
        while index < substrateLen:
            subId = chunk[index]
            index += 1
            if subId < 128:
                reloid += (subId,)
            elif subId > 128:
                # Construct subid from a number of octets
                nextSubId = subId
                subId = 0
                while nextSubId >= 128:
                    subId = (subId << 7) + (nextSubId & 0x7F)
                    if index >= substrateLen:
                        raise error.SubstrateUnderrunError(
                            'Short substrate for sub-OID past %s' % (reloid,)
                        )
                    nextSubId = chunk[index]
                    index += 1
                reloid += ((subId << 7) + nextSubId,)
            elif subId == 128:
                # ASN.1 spec forbids leading zeros (0x80) in OID
                # encoding, tolerating it opens a vulnerability. See page 7 of
                # https://www.esat.kuleuven.be/cosic/publications/article-1432.pdf
                raise error.PyAsn1Error('Invalid octet 0x80 in RELATIVE-OID encoding')

        yield self._createComponent(asn1Spec, tagSet, reloid, **options)


# ----------------------------------------------------------------------
# Additions to the TAG_MAP in pyasn1.type.codec.ber.decoder
# ----------------------------------------------------------------------

if RelativeOID.tagSet not in decoder.TAG_MAP:
    decoder.TAG_MAP.update(
        { RelativeOID.tagSet: RelativeOIDPayloadDecoder(), } )

