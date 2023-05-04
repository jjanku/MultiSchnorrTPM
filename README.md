# MultiSchnorrTPM

This is a small project that explores several ideas for construction of Schnorr multi-signatures for TPMs.

## Setup

Required dependencies: [TPM2-TSS](https://github.com/tpm2-software/tpm2-tss), [TPM2-PyTSS](https://github.com/tpm2-software/tpm2-pytss), [SWTPM](https://github.com/stefanberger/swtpm), and [SageMath](https://www.sagemath.org/).

On Fedora, all dependencies are available from the package manager, see the setup in the CI [workflow file](./.github/workflows/test.yaml).

## Test

Start the TPM emulator using the provided script [run-swtpm.sh](./run-swtpm.sh):

```sh
sh run-swtpm.sh
```

In a separate window, run the tests in [playground.sage](./playground.sage):

```sh
sage playground.sage
```

_Warning_: When a test fails, it may not clean up after itself properly. Subsequent tests are likely to raise an "out of memory for object contexts" exception. In that case, restart the emulator by terminating the scipt and launching it again.

## Useful Links

* [TPM 2.0 Library Specification](https://trustedcomputinggroup.org/resource/tpm-library-specification/) (Part 1: Architecture and Part 3: Commands)
* [TPM2-PyTSS API documentation](https://tpm2-pytss.readthedocs.io/en/latest/api.html)
* [TPM2-PyTSS tests](https://github.com/tpm2-software/tpm2-pytss/tree/master/test): example usage of the API
* [tss2_tpm2_types.h](https://github.com/tpm2-software/tpm2-tss/blob/master/include/tss2/tss2_tpm2_types.h): helpful reference for constructing nested structures required by the API

## Relevant Literature

* [A Practical Guide to TPM 2.0](https://trustedcomputinggroup.org/resource/a-practical-guide-to-tpm-2-0/)
* [A TPM Diffie-Hellman Oracle](https://eprint.iacr.org/2013/667)
* [Efficient and Secure Implementation of BLS Multisignature Scheme on TPM](https://doi.org/10.1109/ISI49825.2020.9280511)
* [One TPM to Bind Them All: Fixing TPM 2.0 for Provably Secure Anonymous Attestation](https://doi.org/10.1109/SP.2017.22)
