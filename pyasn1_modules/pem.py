import base64, sys

stSpam, stHam, stDump = 0, 1, 2

def readPemFromFile(fileObj, startMarker='-----BEGIN CERTIFICATE-----',
                    endMarker='-----END CERTIFICATE-----'):
    state = stSpam
    while 1:
        certLine = fileObj.readline()
        if not certLine:
            break
        certLine = certLine.strip()
        if state == stSpam:
            if certLine == startMarker:
                certLines = []
                state = stHam
                continue
        if state == stHam:
            if certLine == endMarker:
                state = stDump
            else:
                certLines.append(certLine)
        if state == stDump:
            substrate = ''
            for certLine in certLines:
                if sys.version_info[0] <= 2:
                    substrate = substrate + base64.decodestring(certLine)
                else:
                    if not substrate:
                        substrate = substrate.encode()
                    substrate = substrate + base64.decodebytes(
                        certLine.encode()
                        )
            return substrate
