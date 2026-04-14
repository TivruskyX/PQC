# Configuration for Post-Quantum OIDC Server

# Server Configuration
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 8443

# Cryptographic Algorithms
KEM_ALGORITHM = "Kyber512"  # Options: Kyber512, Kyber768, Kyber1024
SIGNATURE_ALGORITHM = "ML-DSA-44"  # Options: ML-DSA-44 (Dilithium2), ML-DSA-65 (Dilithium3), ML-DSA-87 (Dilithium5), Falcon-512, Falcon-1024

# OIDC Configuration
ISSUER = "https://pq-oidc.example.com"
TOKEN_EXPIRY_SECONDS = 3600  # 1 hour
AUTHORIZATION_CODE_EXPIRY = 600  # 10 minutes

# Session Configuration
SESSION_KEY_DERIVATION = "HKDF-SHA256"
SESSION_KEY_LENGTH = 32  # bytes

# Benchmarking
BENCHMARK_ITERATIONS = 1000
BENCHMARK_OUTPUT_DIR = "results"

# Logging
LOG_LEVEL = "INFO"
LOG_FILE = "pq_oidc.log"

# Development Settings
DEBUG_MODE = True
ENABLE_DETAILED_LOGGING = True
