from tpm2_pytss import *
from hashlib import sha256
import hashlib


# NIST P256
# https://neuromancer.sk/std/nist/P-256
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
K = GF(p)
a = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
b = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
E = EllipticCurve(K, (a, b))
G = E(
    0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296,
    0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5
)
E.set_order(
    0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551 * 0x1
)

COORD_LEN = (int(p).bit_length() + 7) // 8
F = GF(E.order())


def tpm_param_to_int(p: TPM2B_ECC_PARAMETER):
    return int.from_bytes(p.buffer.tobytes(), byteorder='big')


def tpm_point_to_sage(P: TPMS_ECC_POINT):
    return E(tpm_param_to_int(P.x), tpm_param_to_int(P.y))


def encode_point(P):
    x, y = map(int, P.xy())
    return (b'\x02' if y % 2 == 0 else b'\x03') + x.to_bytes(COORD_LEN)


def tpm_hash_alg(name):
    if name == 'sha256':
        return TPM2_ALG.SHA256
    elif name == 'sha512':
        return TPM2_ALG.SHA512
    else:
        raise NotImplementedError()


ectx = ESAPI('swtpm:host=localhost')


def ecdaa_commit(key_handle, P=G):
    P1 = TPM2B_ECC_POINT(
        TPMS_ECC_POINT(
            x=int(P[0]).to_bytes(COORD_LEN),
            y=int(P[1]).to_bytes(COORD_LEN)
        )
    )
    _s2 = TPM2B_SENSITIVE_DATA()
    _y2 = TPM2B_ECC_PARAMETER()
    _K, _L, E, counter = ectx.commit(key_handle, P1, _s2, _y2)
    E = tpm_point_to_sage(E.point)
    return counter, E


def ecdaa_sign(key_handle, counter, digest, hash_alg='sha256'):
    in_scheme = TPMT_SIG_SCHEME(
        scheme=TPM2_ALG.ECDAA,
        details=TPMU_SIG_SCHEME(
            ecdaa=TPMS_SCHEME_ECDAA(
                hashAlg=tpm_hash_alg(hash_alg),
                count=counter
            )
        )
    )

    validation = TPMT_TK_HASHCHECK(
        tag=TPM2_ST.HASHCHECK,
        hierarchy=TPM2_RH.NULL
    )

    sig = ectx.sign(key_handle, digest, in_scheme, validation)
    s = tpm_param_to_int(sig.signature.ecdaa.signatureS)
    k = sig.signature.ecdaa.signatureR.buffer.tobytes()
    return s, k


# static ECDH oracle
# https://eprint.iacr.org/2013/667.pdf
def ecdh(key_handle, P, hash_alg='sha256'):
    H = hashlib.new(hash_alg)
    # Q = rP
    counter, Q = ecdaa_commit(key_handle, P)
    digest = H.digest_size * b'\x00'
    # s = r+cx
    s, k = ecdaa_sign(key_handle, counter, digest)
    H.update(k + digest)
    c = F(int.from_bytes(H.digest()))
    # sP = (r+cx)P = rP+cxP = Q+cxP
    return (s * P - Q) / c


def ecdaa_keygen(hash_alg='sha256'):
    in_private = TPM2B_SENSITIVE_CREATE()

    eccParams = TPMS_ECC_PARMS()
    eccParams.scheme.scheme = TPM2_ALG.ECDAA
    eccParams.scheme.details.ecdaa.hashAlg = tpm_hash_alg(hash_alg)
    eccParams.symmetric.algorithm = TPM2_ALG.NULL
    eccParams.kdf.scheme = TPM2_ALG.NULL
    eccParams.curveID = TPM2_ECC.NIST_P256
    in_public = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.ECC,
            nameAlg=TPM2_ALG.SHA256,
            objectAttributes=(
                TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.SIGN_ENCRYPT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN
            ),
            parameters=TPMU_PUBLIC_PARMS(
                eccDetail=eccParams
            ),
        )
    )

    key_handle, out_public, _, _, _ = ectx.create_primary(
        in_private, in_public
    )
    X = tpm_point_to_sage(out_public.publicArea.unique.ecc)
    return key_handle, X


def test_ecdaa():
    key_handle, X1 = ecdaa_keygen()

    counter, R = ecdaa_commit(key_handle)
    msg = b'hello'
    digest = sha256(msg + encode_point(R)).digest()
    s, k = ecdaa_sign(key_handle, counter, digest)

    c = F(int.from_bytes(sha256(k + digest).digest()))
    assert s * G == R + c * X1

    ectx.flush_context(key_handle)


def test_ecdh():
    key_handle, X1 = ecdaa_keygen()

    x2 = F.random_element()
    X2 = x2 * G
    X = ecdh(key_handle, X2)

    assert X == x2 * X1

    ectx.flush_context(key_handle)


def test_ecdaa_multi(group_size=3):
    def unzip(list):
        return zip(*list)

    key_handles, Xs = unzip([ecdaa_keygen() for _ in range(group_size)])

    counters, Rs = unzip([
        ecdaa_commit(key_handle)
        for key_handle in key_handles
    ])
    R = sum(Rs)

    msg = b'hello'
    digest = sha256(msg + encode_point(R)).digest()
    ss, ks = unzip([
        ecdaa_sign(key_handles[i], counters[i], digest)
        for i in range(group_size)
    ])
    s = sum(ss)

    cs = [F(int.from_bytes(sha256(k + digest).digest())) for k in ks]
    assert s * G == R + sum(ci * Xi for ci, Xi in zip(cs, Xs))

    for key_handle in key_handles:
        ectx.flush_context(key_handle)


if __name__ == '__main__':
    test_ecdaa()
    test_ecdh()
    # group size > 3 may cause oom for object contexts
    # since the TPM is accessed directly without a resource manager
    # (such as https://github.com/tpm2-software/tpm2-abrmd)
    test_ecdaa_multi(3)
