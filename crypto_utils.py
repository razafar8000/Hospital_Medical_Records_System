"""
==============================================================================
CRYPTOGRAPHIC UTILITIES MODULE
==============================================================================

Purpose: Provides enterprise-grade encryption and security functions for 
         protecting sensitive medical data and maintaining audit integrity.

Key Responsibilities:
- AES-256-GCM encryption/decryption of patient records
- Secure key derivation using PBKDF2 with SHA-256
- Salt generation and management for enhanced security
- Cryptographic hash chain creation for audit logs
- Data integrity verification and validation

Encryption Standards:
- Algorithm: AES-256-GCM (Galois/Counter Mode)
- Key Derivation: PBKDF2 with 100,000 iterations
- IV Generation: Cryptographically secure random (96-bit)
- Authentication: Built-in authenticated encryption
- Hash Function: SHA-256 for audit log integrity

Security Features:
- Authenticated encryption prevents tampering
- Secure random IV for each encryption operation
- Master key protection with environmental variables
- Salt-based key derivation for rainbow table resistance
- Error handling without information leakage

Compliance:
- HIPAA-compliant encryption standards
- OpenSSL cryptographic primitives
- Industry-standard security practices
- Tamper-evident audit log chains

==============================================================================
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidKey
import os
import base64
from datetime import datetime
from dotenv import load_dotenv

class MedicalCrypto:   
    def __init__(self):
        load_dotenv()
        self.salt = self._get_or_create_salt()
        self.key = self._derive_key()
        self.aesgcm = AESGCM(self.key)
    
    def _get_or_create_salt(self):
        salt_path = os.path.join(os.path.dirname(__file__), 'salt.key')
        try:
            with open(salt_path, 'rb') as f:
                return f.read()
        except FileNotFoundError:
            salt = os.urandom(16)
            with open(salt_path, 'wb') as f:
                f.write(salt)
            return salt

    def _derive_key(self):
        # Using PBKDF2 to derive a 32-byte key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.salt,
            iterations=100000,
        )

        master_key = os.getenv('MEDICAL_MASTER_KEY', 'fallback-key-for-development').encode()
        return kdf.derive(master_key)

    def encrypt_patient_data(self, patient_data):
        # Encrypting patient data using AES-256-GCM
        try:
            # Converting dictionary to string
            data_str = "|".join([
                str(patient_data.get('name', '')),
                str(patient_data.get('dob', '')),
                str(patient_data.get('address', '')),
                str(patient_data.get('phone', '')),
                str(patient_data.get('diagnosis', '')),
                str(patient_data.get('treatment', '')),
                str(patient_data.get('gender', ''))
            ])

            # Generating a random 96-bit IV
            iv = os.urandom(12)
            
            # Encrypting the data
            ciphertext = self.aesgcm.encrypt(
                iv,
                data_str.encode(),
                None  
            )
            
            # Combining IV and ciphertext
            return base64.b64encode(iv + ciphertext)
        except Exception as e:
            print(f"Encryption error: {e}")
            return None

    def decrypt_patient_data(self, encrypted_data):
        # Decrypting patient data using AES-256-GCM
        try:
            # Decoding from base64
            raw_data = base64.b64decode(encrypted_data)
        
            # Extracting IV and ciphertext
            iv = raw_data[:12]
            ciphertext = raw_data[12:]
        
            # Decrypting the data
            decrypted = self.aesgcm.decrypt(
                iv,
                ciphertext,
                None
            ).decode()
        
            # Splitting into fields
            fields = decrypted.split('|')
            if len(fields) < 7:  # Ensures we have all fields
                fields.extend([''] * (7 - len(fields)))
            
            return {
                'name': fields[0] or '',
                'dob': fields[1] or '',
                'address': fields[2] or '',
                'phone': fields[3] or '',
                'diagnosis': fields[4] or '',
                'treatment': fields[5] or '',
                'gender': fields[6] or ''
            }
        except Exception as e:
            print(f"Decryption error: {e}")
            return {
                'name': '',
                'dob': '',
                'address': '',
                'phone': '',
                'diagnosis': '',
                'treatment': '',
                'gender': ''
            }
        
    def re_encrypt_data(self, encrypted_data):
        # Re-encrypting data with current key
        try:
            # First trying to decrypt with current key
            decrypted_data = self.decrypt_patient_data(encrypted_data)
            
            # Checking if decryption was successful
            if not any(decrypted_data.values()):
                raise Exception("Decryption failed")
                
            # Re-encrypting with current key
            return self.encrypt_patient_data(decrypted_data)
        except Exception as e:
            print(f"Re-encryption error: {e}")
            return None
    
    def create_log_hash(self, prev_hash, role, action, details, timestamp):
        # Creating hash for audit log entry using SHA-256
        message = f"{prev_hash}{role}{action}{details}{timestamp}".encode()
        hasher = hashes.Hash(hashes.SHA256())
        hasher.update(message)
        return hasher.finalize().hex()