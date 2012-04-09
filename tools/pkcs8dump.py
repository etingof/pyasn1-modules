# Read  bunch of ASN.1/PEM plain/encrypted private keys in PKCS#8 
# format on stdin, parse each into plain text, then build substrate from it
from pyasn1.codec.der import decoder, encoder
from pyasn1 import error
from pyasn1_modules import rfc5208, pem
import sys

if len(sys.argv) != 1:
    print("""Usage:
$ cat pkcs8key.pem | %s""" % (sys.argv[0], sys.argv[0]))
    sys.exit(-1)
    
keyTypePlain = rfc5208.PrivateKeyInfo()
keyTypeEncrypted = rfc5208.EncryptedPrivateKeyInfo()

cnt = 0

while 1:
    substrate = pem.readPemFromFile(
                    sys.stdin,
                    ('-----BEGIN PRIVATE KEY-----',
                     '-----BEGIN ENCRYPTED PRIVATE KEY-----'),
                    ('-----END PRIVATE KEY-----',
                     '-----END ENCRYPTED PRIVATE KEY-----')
                )
    if not substrate:
        break

    try:        
        key, rest = decoder.decode(substrate, asn1Spec=keyTypeEncrypted)
    except error.PyAsn1Error:
        key, rest = decoder.decode(substrate, asn1Spec=keyTypePlain)

    if rest: substrate = substrate[:-len(rest)]
        
    print(key.prettyPrint())

    assert encoder.encode(key, defMode=False) == substrate or \
           encoder.encode(key, defMode=True) == substrate, \
           'pkcs8 recode fails'
        
    cnt = cnt + 1
    
print('*** %s PKCS#8 key(s) de/serialized' % cnt)
