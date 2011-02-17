# Read ASN.1/PEM PKCS#7 on stdin, parse each into plain text,
# then build substrate from it
from pyasn1_modules import rfc2315, pem
from pyasn1.codec.der import encoder, decoder
import sys
    
if len(sys.argv) != 1:
    print """Usage:
$ cat pkcs7Certificate.pem | %s""" % (sys.argv[0],)
    sys.exit(-1)
    
substrate = pem.readPemFromFile(
    sys.stdin, '-----BEGIN PKCS7-----', '-----END PKCS7-----'
    )

assert substrate, 'bad PKCS7 data on input'
        
contentInfo, rest = decoder.decode(substrate, asn1Spec=rfc2315.ContentInfo())

if rest: substrate = substrate[:-len(rest)]
    
print contentInfo.prettyPrint()

assert encoder.encode(contentInfo, defMode=False) == substrate or \
       encoder.encode(contentInfo, defMode=True) == substrate, \
       're-encode fails'

contentType = contentInfo.getComponentByName('contentType')

contentInfoMap = {
    (1, 2, 840, 113549, 1, 7, 1): rfc2315.Data(),
    (1, 2, 840, 113549, 1, 7, 2): rfc2315.SignedData(),
    (1, 2, 840, 113549, 1, 7, 3): rfc2315.EnvelopedData(),
    (1, 2, 840, 113549, 1, 7, 4): rfc2315.SignedAndEnvelopedData(),
    (1, 2, 840, 113549, 1, 7, 5): rfc2315.DigestedData(),
    (1, 2, 840, 113549, 1, 7, 6): rfc2315.EncryptedData()
    }

content, _ = decoder.decode(
    contentInfo.getComponentByName('content'),
    asn1Spec=contentInfoMap[contentType]
    )

print content.prettyPrint()
