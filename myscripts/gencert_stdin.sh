#!/bin/sh
cat client_config.json | cfssl gencert -config /dev/stdin -profile=user1 -label=default csr.json
