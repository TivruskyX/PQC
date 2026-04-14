#!/usr/bin/env python3
"""
Comprehensive Benchmarking Suite for Post-Quantum OIDC with KEMTLS

Measures:
1. Cryptographic operations (KEM, signatures)
2. KEMTLS handshake performance
3. JWT operations (creation, verification)
4. End-to-end OIDC authentication flow
5. Message sizes

Outputs results to CSV and JSON for analysis and PDF generation.
"""

import sys
import os
import time
import json
import statistics
from typing import Dict, List, Tuple
from dataclasses import dataclass, asdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../..'))

from src.pq_crypto.kem import KyberKEM
from src.pq_crypto.signature import DilithiumSigner
from src.pq_crypto.utils import derive_session_keys
from src.kemtls.protocol import KEMTLSCertificate
from src.kemtls.server import KEMTLSServer
from src.kemtls.client import KEMTLSClient
from src.oidc.pq_jwt import PQJWTHandler
from src.oidc.server import create_demo_server
from src.oidc.client import create_demo_client


@dataclass
class BenchmarkResult:
    """Single benchmark result."""
    operation: str
    algorithm: str
    mean_ms: float
    median_ms: float
    stdev_ms: float
    min_ms: float
    max_ms: float
    iterations: int
    size_bytes: int = 0


class BenchmarkSuite:
    """Comprehensive benchmarking suite."""
    
    def __init__(self, iterations: int = 100):
        """
        Initialize benchmark suite.
        
        Args:
            iterations: Number of iterations for each benchmark
        """
        self.iterations = iterations
        self.results: List[BenchmarkResult] = []
        
    def benchmark_operation(self, name: str, algorithm: str, operation, 
                           iterations: int = None, size_bytes: int = 0) -> BenchmarkResult:
        """
        Benchmark a single operation.
        
        Args:
            name: Operation name
            algorithm: Algorithm name
            operation: Callable to benchmark
            iterations: Number of iterations (uses default if None)
            size_bytes: Size in bytes (for message sizes)
            
        Returns:
            BenchmarkResult with statistics
        """
        iters = iterations or self.iterations
        times = []
        
        print(f"  Benchmarking {name} ({algorithm})...", end=' ', flush=True)
        
        for _ in range(iters):
            start = time.perf_counter()
            operation()
            end = time.perf_counter()
            times.append((end - start) * 1000)  # Convert to ms
            
        result = BenchmarkResult(
            operation=name,
            algorithm=algorithm,
            mean_ms=statistics.mean(times),
            median_ms=statistics.median(times),
            stdev_ms=statistics.stdev(times) if len(times) > 1 else 0,
            min_ms=min(times),
            max_ms=max(times),
            iterations=iters,
            size_bytes=size_bytes
        )
        
        print(f"✓ Mean: {result.mean_ms:.3f} ms")
        
        self.results.append(result)
        return result
        
    def benchmark_kem_operations(self):
        """Benchmark KEM operations for all Kyber variants."""
        print("\n[1] Benchmarking KEM Operations")
        print("=" * 70)
        
        for alg in ["Kyber512", "Kyber768", "Kyber1024"]:
            kem = KyberKEM(algorithm=alg)
            
            # Keygen
            self.benchmark_operation(
                "KEM Keygen",
                alg,
                lambda k=kem: k.generate_keypair()
            )
            
            # Encapsulation
            public_key = kem.generate_keypair()
            ciphertext, _ = kem.encapsulate(public_key)
            
            self.benchmark_operation(
                "KEM Encapsulation",
                alg,
                lambda k=kem, pk=public_key: k.encapsulate(pk),
                size_bytes=len(ciphertext)
            )
            
            # Decapsulation
            self.benchmark_operation(
                "KEM Decapsulation",
                alg,
                lambda k=kem, ct=ciphertext: k.decapsulate(ct)
            )
            
    def benchmark_signature_operations(self):
        """Benchmark signature operations for all supported algorithms."""
        print("\n[2] Benchmarking Signature Operations")
        print("=" * 70)
        
        algorithms = ["ML-DSA-44", "ML-DSA-65", "ML-DSA-87", "Falcon-512", "Falcon-1024"]
        test_message = b"This is a test message for signing performance measurement."
        
        for alg in algorithms:
            try:
                signer = DilithiumSigner(algorithm=alg)
                
                # Keygen
                self.benchmark_operation(
                    "Signature Keygen",
                    alg,
                    lambda s=signer: s.generate_keypair()
                )
                
                # Signing
                public_key = signer.generate_keypair()
                signature = signer.sign(test_message)
                
                self.benchmark_operation(
                    "Sign",
                    alg,
                    lambda s=signer, msg=test_message: s.sign(msg),
                    size_bytes=len(signature)
                )
                
                # Verification
                self.benchmark_operation(
                    "Verify",
                    alg,
                    lambda s=signer, msg=test_message, sig=signature, pk=public_key: s.verify(msg, sig, pk)
                )
                
            except Exception as e:
                print(f"  Skipping {alg}: {e}")
                
    def benchmark_kemtls_handshake(self):
        """Benchmark KEMTLS handshake process."""
        print("\n[3] Benchmarking KEMTLS Handshake")
        print("=" * 70)
        
        kem = KyberKEM(algorithm="Kyber512")
        signer = DilithiumSigner(algorithm="ML-DSA-44")
        
        # Generate server certificate once
        server_kem_public = kem.generate_keypair()
        server_sig_public = signer.generate_keypair()
        
        server_cert = KEMTLSCertificate(
            subject="Benchmark Server",
            kem_public_key=server_kem_public,
            sig_public_key=server_sig_public
        )
        
        def full_handshake():
            """Simulate full KEMTLS handshake."""
            # Client generates ephemeral keys
            client_public = kem.generate_keypair()
            
            # Server encapsulates to client key
            ciphertext, shared_secret_server = kem.encapsulate(client_public)
            
            # Client decapsulates
            shared_secret_client = kem.decapsulate(ciphertext)
            
            # Derive session keys
            session_keys = derive_session_keys(shared_secret_client, b"kemtls-benchmark")
            
            return session_keys
            
        self.benchmark_operation(
            "Full KEMTLS Handshake",
            "Kyber512 + ML-DSA-44",
            full_handshake,
            iterations=50  # Fewer iterations for complete handshake
        )
        
        # Measure handshake message sizes
        client_public = kem.generate_keypair()
        ciphertext, _ = kem.encapsulate(client_public)
        
        handshake_size = (
            len(client_public) +                # ClientHello
            len(ciphertext) +                   # ServerHello ciphertext
            len(server_cert.kem_public_key) +   # Server cert KEM key
            len(server_cert.sig_public_key)     # Server cert sig key
        )
        
        print(f"\n  Handshake Message Sizes:")
        print(f"    Client ephemeral key: {len(client_public)} bytes")
        print(f"    Server ciphertext: {len(ciphertext)} bytes")
        print(f"    Server certificate: {len(server_cert.kem_public_key) + len(server_cert.sig_public_key)} bytes")
        print(f"    Total handshake: {handshake_size} bytes")
        
    def benchmark_jwt_operations(self):
        """Benchmark JWT creation and verification."""
        print("\n[4] Benchmarking JWT Operations")
        print("=" * 70)
        
        algorithms = ["ML-DSA-44", "ML-DSA-65", "Falcon-512"]
        issuer = "http://localhost:5000"
        
        for alg in algorithms:
            handler = PQJWTHandler(algorithm=alg, issuer=issuer)
            handler.generate_keypair()
            
            # JWT Creation
            def create_jwt():
                return handler.create_id_token(
                    user_id="user123",
                    client_id="test-client",
                    nonce="test-nonce",
                    additional_claims={
                        "email": "test@example.com",
                        "name": "Test User"
                    }
                )
            
            token = create_jwt()
            
            self.benchmark_operation(
                "JWT Creation",
                alg,
                create_jwt,
                size_bytes=len(token)
            )
            
            # JWT Verification
            self.benchmark_operation(
                "JWT Verification",
                alg,
                lambda: handler.verify_jwt(token, audience="test-client", issuer=issuer)
            )
            
    def benchmark_oidc_flow(self):
        """Benchmark complete OIDC authentication flow."""
        print("\n[5] Benchmarking Complete OIDC Flow")
        print("=" * 70)
        
        server = create_demo_server()
        client = create_demo_client()
        client.jwt_handler.public_key = server.jwt_handler.public_key
        
        def complete_flow():
            """Simulate complete OIDC authorization code flow."""
            # 1. Generate authorization URL
            auth_url = client.get_authorization_url()
            
            # 2. User authentication
            user_id = server.authenticate_user("alice", "password123")
            session_id = server.create_session(user_id)
            
            # 3. Authorization request
            redirect_url, _ = server.handle_authorization_request(
                response_type="code",
                client_id=client.client_id,
                redirect_uri=client.redirect_uri,
                scope="openid profile email",
                state="test-state",
                nonce="test-nonce",
                session_id=session_id
            )
            
            # 4. Extract code
            from urllib.parse import urlparse, parse_qs
            params = parse_qs(urlparse(redirect_url).query)
            code = params['code'][0]
            
            # 5. Token exchange
            tokens, _ = server.handle_token_request(
                grant_type="authorization_code",
                code=code,
                redirect_uri=client.redirect_uri,
                client_id=client.client_id,
                client_secret=client.client_secret
            )
            
            # 6. Token verification
            claims = client.verify_id_token(
                tokens['id_token'],
                expected_nonce="test-nonce"
            )
            
            return claims
            
        self.benchmark_operation(
            "End-to-End OIDC Flow",
            "Complete Authorization Code Flow",
            complete_flow,
            iterations=20  # Fewer iterations for complete flow
        )
        
    def save_results(self, output_dir: str = "benchmark_results"):
        """
        Save benchmark results to JSON and CSV.
        
        Args:
            output_dir: Directory to save results
        """
        os.makedirs(output_dir, exist_ok=True)
        
        # Save as JSON
        json_path = os.path.join(output_dir, "benchmark_results.json")
        with open(json_path, 'w') as f:
            json.dump([asdict(r) for r in self.results], f, indent=2)
        print(f"\n✓ Saved JSON results to: {json_path}")
        
        # Save as CSV
        csv_path = os.path.join(output_dir, "benchmark_results.csv")
        with open(csv_path, 'w') as f:
            # Header
            f.write("Operation,Algorithm,Mean (ms),Median (ms),Stdev (ms),Min (ms),Max (ms),Iterations,Size (bytes)\n")
            
            # Data
            for r in self.results:
                f.write(f'"{r.operation}","{r.algorithm}",{r.mean_ms:.4f},{r.median_ms:.4f},'
                       f'{r.stdev_ms:.4f},{r.min_ms:.4f},{r.max_ms:.4f},{r.iterations},{r.size_bytes}\n')
        print(f"✓ Saved CSV results to: {csv_path}")
        
    def print_summary(self):
        """Print summary of benchmark results."""
        print("\n" + "=" * 70)
        print("BENCHMARK SUMMARY")
        print("=" * 70)
        
        print("\n{:<35} {:<25} {:>10}".format("Operation", "Algorithm", "Mean (ms)"))
        print("-" * 70)
        
        for result in self.results:
            print("{:<35} {:<25} {:>10.3f}".format(
                result.operation,
                result.algorithm,
                result.mean_ms
            ))
            
        print("\n" + "=" * 70)


def main():
    """Run comprehensive benchmark suite."""
    print("╔══════════════════════════════════════════════════════════════════╗")
    print("║  POST-QUANTUM OIDC WITH KEMTLS - BENCHMARK SUITE                ║")
    print("╚══════════════════════════════════════════════════════════════════╝")
    
    print("\nInitializing benchmark suite...")
    suite = BenchmarkSuite(iterations=100)
    
    print(f"Configuration:")
    print(f"  Iterations per benchmark: {suite.iterations}")
    print(f"  Python version: {sys.version.split()[0]}")
    
    try:
        # Run all benchmarks
        suite.benchmark_kem_operations()
        suite.benchmark_signature_operations()
        suite.benchmark_kemtls_handshake()
        suite.benchmark_jwt_operations()
        suite.benchmark_oidc_flow()
        
        # Print summary
        suite.print_summary()
        
        # Save results
        suite.save_results()
        
        print("\n✅ Benchmark suite completed successfully!")
        print("\nResults saved to: benchmark_results/")
        print("  • benchmark_results.json")
        print("  • benchmark_results.csv")
        
    except KeyboardInterrupt:
        print("\n\nBenchmark interrupted by user.")
    except Exception as e:
        print(f"\n\n❌ Benchmark failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
        
    return 0


if __name__ == "__main__":
    sys.exit(main())
