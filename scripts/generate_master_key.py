#!/usr/bin/env python3
"""
Generate a secure master encryption key for Vault API.
This key is used to derive project-specific encryption keys.

SECURITY WARNING:
- Store this key securely (use a secrets manager in production)
- Never commit it to version control
- Rotate it periodically
- Backup it securely before rotation
"""

import os
import base64
import sys

def generate_master_key():
    """Generate a 256-bit (32 bytes) master key."""
    key = os.urandom(32)
    encoded_key = base64.b64encode(key).decode('utf-8')
    return encoded_key

if __name__ == "__main__":
    print("=" * 60)
    print("VAULT API - Master Encryption Key Generator")
    print("=" * 60)
    print()
    
    key = generate_master_key()
    
    print("Your master encryption key:")
    print()
    print(f"MASTER_ENCRYPTION_KEY={key}")
    print()
    print("=" * 60)
    print("IMPORTANT:")
    print("1. Add this to your .env file")
    print("2. NEVER commit this key to version control")
    print("3. Store it securely (use AWS Secrets Manager, etc.)")
    print("4. Backup this key before using in production")
    print("=" * 60)
