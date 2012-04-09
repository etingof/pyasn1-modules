import base64, sys

stSpam, stHam, stDump = 0, 1, 2

# The markers parameters is in form ('start1', 'stop1'), ('start2', 'stop2')...
# Return is (marker-index, substrate)
def readPemFromFile(fileObj, *markers):
    startMarkers = dict(map(lambda x: (x[1],x[0]),
                            enumerate(map(lambda x: x[0], markers))))
    stopMarkers = dict(map(lambda x: (x[1],x[0]),
                           enumerate(map(lambda x: x[1], markers))))
    idx = -1; substrate = ''
    state = stSpam
    while 1:
        certLine = fileObj.readline()
        if not certLine:
            break
        certLine = certLine.strip()
        if state == stSpam:
            if certLine in startMarkers:
                certLines = []
                idx = startMarkers[certLine]
                state = stHam
                continue
        if state == stHam:
            if certLine in stopMarkers and stopMarkers[certLine] == idx:
                state = stDump
            else:
                certLines.append(certLine)
        if state == stDump:
            if sys.version_info[0] <= 2:
                substrate = ''.join([ base64.decodestring(x) for x in certLines ])
            else:
                substrate = ''.encode().join([ base64.decodebytes(x.encode()) for x in certLines ])
            break
    return idx, substrate

def readBase64FromFile(fileObj):
    if sys.version_info[0] <= 2:
        return ''.join([ base64.decodestring(x) for x in fileObj.readlines() ])
    else:
        return ''.encode().join(
            [ base64.decodebytes(x.encode()) for x in fileObj.readlines() ]
        )
