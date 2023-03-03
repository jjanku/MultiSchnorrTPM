#!/bin/sh
rm -r swtpm-state
mkdir swtpm-state
swtpm socket \
    --server type=tcp,port=2321 \
    --ctrl type=tcp,port=2322 \
    --tpmstate dir=./swtpm-state \
    --tpm2 \
    --flags not-need-init,startup-clear \
    --log level=20
