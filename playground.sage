from tpm2_pytss import *
from hashlib import sha256


# P256
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

coord_len = (int(p).bit_length() + 7) // 8
F = GF(E.order())


def param_to_int(p: TPM2B_ECC_PARAMETER):
    return int.from_bytes(p.buffer.tobytes(), byteorder='big')


def point_to_sage(P: TPMS_ECC_POINT):
    return E(param_to_int(P.x), param_to_int(P.y))


ectx = ESAPI('swtpm:host=localhost')


def ecdaa_commit(key_handle, P=G):
    P1 = TPM2B_ECC_POINT(
        TPMS_ECC_POINT(
            x=int(P[0]).to_bytes(coord_len),
            y=int(P[1]).to_bytes(coord_len)
        )
    )
    _s2 = TPM2B_SENSITIVE_DATA()
    _y2 = TPM2B_ECC_PARAMETER()
    _K, _L, E, counter = ectx.commit(key_handle, P1, _s2, _y2)
    E = point_to_sage(E.point)
    return counter, E


def ecdaa_sign(key_handle, counter, digest):
    in_scheme = TPMT_SIG_SCHEME(
        scheme=TPM2_ALG.ECDAA,
        details=TPMU_SIG_SCHEME(
            ecdaa=TPMS_SCHEME_ECDAA(
                hashAlg=TPM2_ALG.SHA256,
                count=counter
            )
        )
    )

    validation = TPMT_TK_HASHCHECK(
        tag=TPM2_ST.HASHCHECK,
        hierarchy=TPM2_RH.NULL
    )

    sig = ectx.sign(key_handle, digest, in_scheme, validation)
    s = param_to_int(sig.signature.ecdaa.signatureS)
    k = sig.signature.ecdaa.signatureR.buffer.tobytes()
    return s, k


# https://eprint.iacr.org/2013/667.pdf
def ecdh(key_handle, P):
    # Q = rP
    counter, Q = ecdaa_commit(key_handle, P)
    digest = 32 * b'\x00'
    # s = r+cx
    s, k = ecdaa_sign(key_handle, counter, digest)
    c = F(int.from_bytes(sha256(k + digest).digest()))
    # sP = (r+cx)P = rP+cxP = Q+cxP
    return (s * P - Q) / c


def keygen():
    in_private = TPM2B_SENSITIVE_CREATE()

    eccParams = TPMS_ECC_PARMS()
    eccParams.scheme.scheme = TPM2_ALG.ECDH
    eccParams.scheme.details.ecdh.hashAlg = TPM2_ALG.NULL
    eccParams.symmetric.algorithm = TPM2_ALG.NULL
    eccParams.kdf.scheme = TPM2_ALG.NULL
    eccParams.curveID = TPM2_ECC.NIST_P256
    in_public = TPM2B_PUBLIC(
        publicArea=TPMT_PUBLIC(
            type=TPM2_ALG.ECC,
            nameAlg=TPM2_ALG.SHA256,
            objectAttributes=(
                TPMA_OBJECT.USERWITHAUTH
                | TPMA_OBJECT.DECRYPT
                | TPMA_OBJECT.FIXEDTPM
                | TPMA_OBJECT.FIXEDPARENT
                | TPMA_OBJECT.SENSITIVEDATAORIGIN
            ),
            parameters=TPMU_PUBLIC_PARMS(
                eccDetail=eccParams
            ),
        )
    )

    key_handle, out_public, _, _, _ = ectx.create_primary(in_private, in_public)
    X = point_to_sage(out_public.publicArea.unique.ecc)
    return key_handle, X


def test_ecdaa():
    key_handle, X1 = keygen()

    msg = b'hello'
    digest = sha256(msg).digest()
    counter, R = ecdaa_commit(key_handle)
    s, k = ecdaa_sign(key_handle, counter, digest)
    c = int.from_bytes(sha256(k + digest).digest())
    assert s * G == R + c * X1

    ectx.flush_context(key_handle)


def test_ecdh():
    key_handle, X1 = keygen()

    x2 = F.random_element()
    X2 = x2 * G
    X = ecdh(key_handle, X2)
    assert X == x2 * X1

    ectx.flush_context(key_handle)


def test_ecdaa_multi():
    def unzip(list):
        return zip(*list)

    # higher number may cause oom for object contexts
    GROUP_SIZE = 3
    key_handles, Xs = unzip([keygen() for _ in range(GROUP_SIZE)])

    msg = b'hello'
    digest = sha256(msg).digest()
    counters, Rs = unzip([
        ecdaa_commit(key_handle)
        for key_handle in key_handles
    ])
    ss, ks = unzip([
        ecdaa_sign(key_handles[i], counters[i], digest)
        for i in range(GROUP_SIZE)
    ])
    cs = [int.from_bytes(sha256(k + digest).digest()) for k in ks]
    s = sum(ss)
    R = sum(Rs)
    assert s * G == R + sum(ci * Xi for ci, Xi in zip(cs, Xs))

    for key_handle in key_handles:
        ectx.flush_context(key_handle)


if __name__ == '__main__':
    # test_ecdaa()
    # test_ecdh()
    # test_ecdaa_multi()
    keygen()
