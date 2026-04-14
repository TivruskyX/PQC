#!/usr/bin/env python3
"""
Quick Test - Run all component tests
"""

import sys
import os

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

print("="*70)
print("QUICK TEST - Post-Quantum OIDC Components")
print("="*70)

print("\n1. Testing Post-Quantum Cryptography...")
print("-" * 70)
from src.pq_crypto import test_crypto
test_crypto.main()

print("\n2. Testing KEMTLS Protocol...")
print("-" * 70)
from src.kemtls import protocol
protocol.test_kemtls_messages()

print("\n3. Testing KEMTLS Server...")
print("-" * 70)
from src.kemtls import server
server.test_kemtls_server()

print("\n4. Testing KEMTLS Client...")
print("-" * 70)
from src.kemtls import client
client.test_kemtls_client()

print("\n5. Testing Post-Quantum JWT...")
print("-" * 70)
from src.oidc import pq_jwt
pq_jwt.test_pq_jwt()

print("\n" + "="*70)
print("✅ ALL TESTS PASSED!")
print("="*70)
print("\nAll core components are working correctly.")
print("Run 'python3 examples/interactive_demo.py' for detailed demonstration.")
