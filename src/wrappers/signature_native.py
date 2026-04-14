import ctypes
import os

lib_path = os.path.join(os.path.dirname(__file__), "../../wasm/signature.so")
lib = ctypes.CDLL(lib_path)

def signature_test(message: bytes):
    PK_LEN = 1312
    SIG_LEN = 2420

    public_key = ctypes.create_string_buffer(PK_LEN)
    signature = ctypes.create_string_buffer(SIG_LEN)
    result = ctypes.create_string_buffer(1)

    lib.signature_test(
        message,
        len(message),
        public_key,
        signature,
        result
    )

    return {
        "public_key": public_key.raw,
        "signature": signature.raw,
        "valid": bool(result[0])
    }
