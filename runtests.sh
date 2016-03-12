#!/bin/sh

set -e

export PATH=tools:$PATH

for script in test/*.sh
do
  ${script}
done