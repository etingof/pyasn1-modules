import base64

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
                certLines.append(certLine.encode())
        if state == stDump:
            substrate = ''.encode()
            for certLine in certLines:
                substrate = substrate + base64.decodestring(certLine)
            return substrate
