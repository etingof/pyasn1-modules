# Read unencrypted PKCS#1/PKIX-compliant, PEM&DER encoded private keys on
# stdin, print them pretty and encode back into original wire format.
# Private keys can be generated with "openssl genrsa|gendsa" commands.
import sys, base64
from pyasn1_modules import rfc2459, rfc2437
from pyasn1.codec.der import encoder, decoder

keyMagic = {
    '-----BEGIN DSA PRIVATE KEY-----':
    {'-----END DSA PRIVATE KEY-----': rfc2459.DSAPrivateKey() },
    '-----BEGIN RSA PRIVATE KEY-----':
    {'-----END RSA PRIVATE KEY-----': rfc2437.RSAPrivateKey() }
    }

# Read PEM keys from stdin and print them out in plain text

if len(sys.argv) != 1:
    print("""Usage:
$ openssl genrsa -out /tmp/myprivatekey.pem
$ cat /tmp/myprivatekey.pem | %s""" % sys.argv[0])
    sys.exit(-1)
                                
stSpam, stHam, stDump = 0, 1, 2
state = stSpam
keyCnt = 0

for keyLine in sys.stdin.readlines():
    keyLine = keyLine.strip()
    if state == stSpam:
        if keyLine in keyMagic:
            keyMagicTail = keyMagic[keyLine]
            keyLines = []
            state = stHam
            continue
    if state == stHam:
        if keyLine in keyMagicTail:
            asn1Spec = keyMagicTail[keyLine]
            state = stDump
        else:
            keyLines.append(keyLine.encode())
    if state == stDump:
        substrate = ''.encode()
        try:
            for keyLine in keyLines:
                substrate = substrate + base64.decodestring(keyLine)
        except TypeError:
            print('%s, possibly encrypted key' % (sys.exc_info()[1], ))
            state = stSpam
            continue

        key, rest = decoder.decode(substrate, asn1Spec=asn1Spec)

        if rest: substrate = substrate[:-len(rest)]
        
        print(key.prettyPrint())
        
        assert encoder.encode(key) == substrate, 'key re-code fails'
        
        keyCnt = keyCnt + 1
        state = stSpam

print('*** %s private key(s) re/serialized' % keyCnt)
