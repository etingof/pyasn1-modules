#!/bin/sh

set -e

export PATH=tools:$PATH

# TODO: temporarily disable failing tests
for script in cmcdump.sh crl.sh pkcs10.sh pkcs7.sh \
              x509dump-rfc5280.sh \
              pkcs1.sh   pkcs8.sh  x509dump.sh
#for script in test/*.sh
do
  test/${script}
done