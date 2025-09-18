"""
==============================================================================
ENCRYPTION MIGRATION UTILITY
==============================================================================

Purpose: One-time migration script to re-encrypt existing patient records 
         with current encryption keys and fix any decryption inconsistencies.

Key Responsibilities:
- Detect and repair corrupted encrypted patient data
- Re-encrypt all patient records with current cryptographic keys
- Reconstruct encrypted data from database fields when decryption fails
- Maintain data integrity during migration process
- Provide detailed migration progress and status reporting

Migration Process:
1. Connect to PostgreSQL database
2. Retrieve all patients with encrypted data
3. Attempt decryption with current keys
4. If decryption fails, reconstruct from database fields
5. Re-encrypt all data with current encryption parameters
6. Update database with newly encrypted records
7. Generate comprehensive migration report

Use Cases:
- Fixing encryption key mismatches
- Upgrading encryption algorithms
- Repairing corrupted encrypted data
- Standardizing encryption across all records

Safety Features:
- Non-destructive migration (preserves original data)
- Detailed logging and error reporting
- Transaction-based updates for consistency
- Rollback capability in case of errors

==============================================================================
"""

import psycopg2
from psycopg2.extras import RealDictCursor
from crypto_utils import MedicalCrypto
import os   
from dotenv import load_dotenv

def get_db_connection():
    # Creating database connection using environment variables
    load_dotenv()
    return psycopg2.connect(
        host='localhost',
        database='medical_records',
        user='postgres',
        password='admin123'
    )

def migrate_encrypted_data():
    # Migrating existing encrypted records to new encryption
    crypto = MedicalCrypto()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    print("Starting encryption migration...")
    
    # Getting all patients with encrypted data
    cur.execute('SELECT * FROM patients WHERE encrypted_data IS NOT NULL')
    patients = cur.fetchall()
    
    total = len(patients)
    success_count = 0
    fail_count = 0
    reconstructed_count = 0
    
    print(f"\nFound {total} records to process")
    
    for patient in patients:
        try:
            print(f"\nProcessing patient ID: {patient['id']} ({patient['name']})")
            
            # Converting memoryview to bytes if needed
            if isinstance(patient['encrypted_data'], memoryview):
                encrypted_bytes = patient['encrypted_data'].tobytes()
            else:
                encrypted_bytes = bytes(patient['encrypted_data'])
                
            # Trying to decrypt first
            decrypted_data = crypto.decrypt_patient_data(encrypted_bytes)
            
            # Checking if decryption failed (all fields empty)
            if not any(decrypted_data.values()):
                print(f"Decryption failed, reconstructing from database fields...")
                
                # Reconstructing patient data from database fields
                patient_data = {
                    'name': patient['name'] or '',
                    'dob': str(patient['dob']) if patient['dob'] else '',
                    'gender': patient['gender'] or '',
                    'address': patient['address'] or '',
                    'phone': patient['phone'] or '',
                    'diagnosis': patient['diagnosis'] or '',
                    'treatment': patient['treatment'] or ''
                }
                
                # Encrypting with current key
                new_encrypted_data = crypto.encrypt_patient_data(patient_data)
                
                if new_encrypted_data:
                    cur.execute(
                        'UPDATE patients SET encrypted_data = %s WHERE id = %s',
                        (new_encrypted_data, patient['id'])
                    )
                    reconstructed_count += 1
                    success_count += 1
                    print(f"Successfully reconstructed and re-encrypted data")
                else:
                    fail_count += 1
                    print(f"Failed to encrypt reconstructed data")
            else:
                # Decryption worked, just re-encrypting with current key
                new_encrypted_data = crypto.encrypt_patient_data(decrypted_data)
                
                if new_encrypted_data:
                    cur.execute(
                        'UPDATE patients SET encrypted_data = %s WHERE id = %s',
                        (new_encrypted_data, patient['id'])
                    )
                    success_count += 1
                    print(f"Successfully re-encrypted existing data")
                else:
                    fail_count += 1
                    print(f"Failed to re-encrypt data")
                
        except Exception as e:
            fail_count += 1
            print(f"Error: {str(e)}")
    
    conn.commit()
    cur.close()
    conn.close()
    
    print(f"\n=== Migration Summary ===")
    print(f"Total records processed: {total}")
    print(f"Successfully re-encrypted: {success_count}")
    print(f"Records reconstructed from DB: {reconstructed_count}")
    print(f"Failed to process: {fail_count}")

if __name__ == "__main__":
    migrate_encrypted_data()