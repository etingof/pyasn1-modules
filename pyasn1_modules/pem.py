import base64, sys

stSpam, stHam, stDump = 0, 1, 2

def readPemFromFile(fileObj, startMarker, endMarker):
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
            if sys.version_info[0] <= 2:
                return ''.join([ base64.decodestring(x) for x in certLines ])
            else:
                return ''.encode().join([ base64.decodebytes(x.encode()) for x in certLines ])

def readBase64FromFile(fileObj):
    if sys.version_info[0] <= 2:
        return ''.join([ base64.decodestring(x) for x in fileObj.readlines() ])
    else:
        return ''.encode().join(
            [ base64.decodebytes(x.encode()) for x in fileObj.readlines() ]
        )
