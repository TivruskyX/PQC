#!/usr/bin/env python3
"""
Quick test script to verify UI endpoints work correctly
"""

import requests
import json

BASE_URL = "http://localhost:5000"

def test_jwt():
    """Test JWT creation endpoint"""
    print("\n=== Testing JWT Creation ===")
    response = requests.post(f"{BASE_URL}/api/jwt/create", 
                            json={"algorithm": "ML-DSA-44", "user_id": "test_user"})
    data = response.json()
    
    if data.get('success'):
        print(f"✓ JWT created: {data['token_size']} bytes")
        print(f"✓ Create time: {data['create_time_ms']} ms")
        print(f"✓ Verify time: {data['verify_time_ms']} ms")
        print(f"✓ Claims: {data['claims'].get('sub')}")
    else:
        print(f"✗ Error: {data.get('error')}")
    
    return data.get('success', False)

def test_oidc_flow():
    """Test complete OIDC flow endpoint"""
    print("\n=== Testing OIDC Flow ===")
    response = requests.post(f"{BASE_URL}/api/oidc/flow",
                            json={"username": "demo_user", "password": "demo123"})
    data = response.json()
    
    if data.get('success'):
        print(f"✓ OIDC flow completed: {data['total_time_ms']} ms")
        print(f"✓ Steps completed: {len(data['steps'])}")
        for step in data['steps']:
            print(f"  - Step {step['step']}: {step['name']} ({step['time_ms']} ms)")
    else:
        print(f"✗ Error: {data.get('error')}")
    
    return data.get('success', False)

def test_kemtls():
    """Test KEMTLS handshake endpoint"""
    print("\n=== Testing KEMTLS Handshake ===")
    response = requests.post(f"{BASE_URL}/api/kemtls/handshake",
                            json={"algorithm": "Kyber768"})
    data = response.json()
    
    if data.get('success'):
        print(f"✓ Handshake completed: {data['total_time_ms']} ms")
        print(f"✓ Secrets match: {data['secrets_match']}")
    else:
        print(f"✗ Error: {data.get('error')}")
    
    return data.get('success', False)

def test_signatures():
    """Test signatures endpoint"""
    print("\n=== Testing Digital Signatures ===")
    response = requests.post(f"{BASE_URL}/api/signatures/test",
                            json={"algorithm": "ML-DSA-44", "message": "Test message"})
    data = response.json()
    
    if data.get('success'):
        print(f"✓ Signature test completed: {data['total_time_ms']} ms")
        print(f"✓ Valid signature: {data['is_valid']}")
        print(f"✓ Invalid rejected: {data['invalid_rejected']}")
    else:
        print(f"✗ Error: {data.get('error')}")
    
    return data.get('success', False)

if __name__ == "__main__":
    print("="*60)
    print("Testing Post-Quantum OIDC UI Endpoints")
    print("="*60)
    
    try:
        results = {
            'KEMTLS': test_kemtls(),
            'Signatures': test_signatures(),
            'JWT': test_jwt(),
            'OIDC Flow': test_oidc_flow()
        }
        
        print("\n" + "="*60)
        print("Test Summary")
        print("="*60)
        for name, passed in results.items():
            status = "✓ PASS" if passed else "✗ FAIL"
            print(f"{status} - {name}")
        
        all_passed = all(results.values())
        print("\n" + ("="*60))
        if all_passed:
            print("✓ ALL TESTS PASSED")
        else:
            print("✗ SOME TESTS FAILED")
        print("="*60 + "\n")
        
    except requests.exceptions.ConnectionError:
        print("\n✗ ERROR: Could not connect to UI server at", BASE_URL)
        print("Make sure the UI is running: python ui/app.py")
    except Exception as e:
        print(f"\n✗ ERROR: {e}")
