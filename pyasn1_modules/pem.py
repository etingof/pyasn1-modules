import base64, string

stSpam, stHam, stDump = 0, 1, 2

def readPemFromFile(fileObj, startMarker='-----BEGIN CERTIFICATE-----',
                    endMarker='-----END CERTIFICATE-----'):
    state = stSpam
    while 1:
        certLine = fileObj.readline()
        if not certLine:
            break
        certLine = string.strip(certLine)
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
                substrate = substrate + base64.decodestring(certLine)
            return substrate
