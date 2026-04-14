import ctypes
import os

lib_path = os.path.join(os.path.dirname(__file__), "../../wasm/kemtls.so")
lib = ctypes.CDLL(lib_path)

# 🔥 ADD THIS BLOCK (CRITICAL FIX)
lib.kemtls_handshake_timed.argtypes = [
    ctypes.c_char_p,      # alg_name
    ctypes.c_void_p,      # public_key
    ctypes.c_void_p,      # ciphertext
    ctypes.c_void_p,      # shared_secret
    ctypes.POINTER(ctypes.c_double),
    ctypes.POINTER(ctypes.c_double),
    ctypes.POINTER(ctypes.c_double)
]

lib.kemtls_handshake_timed.restype = None


def kemtls_handshake(algorithm="Kyber512"):

    alg_map = {
        "Kyber512": b"Kyber512",
        "Kyber768": b"Kyber768",
        "Kyber1024": b"Kyber1024"
    }

    alg = alg_map.get(algorithm, b"Kyber512")

    PK_LEN = 1568
    CT_LEN = 1568
    SS_LEN = 32

    public_key = ctypes.create_string_buffer(PK_LEN)
    ciphertext = ctypes.create_string_buffer(CT_LEN)
    shared_secret = ctypes.create_string_buffer(SS_LEN)

    keygen_time = ctypes.c_double()
    encap_time = ctypes.c_double()
    decap_time = ctypes.c_double()

    lib.kemtls_handshake_timed(
        alg,
        public_key,
        ciphertext,
        shared_secret,
        ctypes.byref(keygen_time),
        ctypes.byref(encap_time),
        ctypes.byref(decap_time)
    )

    return {
        "public_key": public_key.raw,
        "ciphertext": ciphertext.raw,
        "shared_secret": shared_secret.raw,
        "keygen_time": keygen_time.value,
        "encap_time": encap_time.value,
        "decap_time": decap_time.value
    }
