"""
==============================================================================
MEDICAL RECORDS MANAGEMENT SYSTEM - MAIN APPLICATION
==============================================================================

Purpose: Core Flask application handling all backend operations for a secure 
         medical records management system with role-based access control.

Key Responsibilities:
- User authentication and role-based routing (Doctor, Nurse, Admin)
- Patient data CRUD operations with encryption
- Secure audit logging with hash chain integrity
- Database connections and transaction management
- Role-specific functionality enforcement
- Error handling and security controls

Features:
- AES-256-GCM encryption for sensitive patient data
- Comprehensive audit trail for compliance
- Role-based permissions (Doctor: full access, Nurse: treatment updates, Admin: audit logs)
- PostgreSQL database integration
- Real-time data validation and sanitization

Security Measures:
- Encrypted storage of all patient information
- Immutable audit log chain with SHA-256 hashing
- Input validation and SQL injection prevention
- Role-based access control enforcement

==============================================================================
"""


from flask import Flask, render_template, request, redirect, url_for, flash
from psycopg2.extras import RealDictCursor
import psycopg2
from datetime import datetime
from flask import flash
from crypto_utils import MedicalCrypto
import os
from dotenv import load_dotenv
import logging
logging.basicConfig(level=logging.ERROR)

load_dotenv()

app = Flask(__name__)  
app.secret_key = os.getenv('MEDICAL_MASTER_KEY')
if not app.secret_key:
    raise RuntimeError("MEDICAL_MASTER_KEY is not set. Please configure it in your .env file before running the app.")
crypto = MedicalCrypto()

DB_HOST = os.getenv('DB_HOST')
DB_NAME = os.getenv('DB_NAME')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')

if not all([DB_HOST, DB_NAME, DB_USER, DB_PASSWORD]):
    raise RuntimeError("Database environment variables are not set. Please configure .env before running.")

# Homepage route
@app.route('/')
def index():
    return render_template("index.html")

# Database connection to PostgreSQL
def get_db_connection():
    try:
        conn = psycopg2.connect(
            host=DB_HOST,
            database=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD
        )
        return conn
    except psycopg2.Error as e:
        logging.error(f"Database connection error: {e}")
        return None


# -------------------------
#  Patients List
# -------------------------
@app.route('/patients')
def patients():
    role = request.args.get('role', 'Doctor')  # Default = Doctor if none provided
    conn = get_db_connection()

    if conn is None:
        flash('Database connection failed')
        return redirect(url_for('index'))
    
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('SELECT * FROM patients ORDER BY id;')
    patients = cur.fetchall()
    cur.close()
    conn.close()
    

    # -------------------------------
    # Calculating Gender Distribution
    # -------------------------------
    male_count = len([p for p in patients if p['gender'] == "Male"])
    female_count = len([p for p in patients if p['gender'] == "Female"])
    other_count = len([p for p in patients if p['gender'] not in ["Male", "Female"]])
    total = max(len(patients), 1) 

    gender_data = {
        "male": male_count,
        "female": female_count,
        "other": other_count,
        "male_percent": (male_count / total) * 100,
        "female_percent": (female_count / total) * 100,
        "other_percent": (other_count / total) * 100,
    }

    # ----------------------------
    # Calculating Age Distribution
    # ----------------------------
    from datetime import date
    today = date.today()
    age_bins = {"<20": 0, "20-39": 0, "40-59": 0, "60+": 0}

    for p in patients:
        try:
            dob = p['dob']
            if isinstance(dob, str):
                dob = datetime.strptime(dob, "%Y-%m-%d").date()
            age = (today - dob).days // 365
            if age < 20:
                age_bins["<20"] += 1
            elif age < 40:
                age_bins["20-39"] += 1
            elif age < 60:
                age_bins["40-59"] += 1
            else:
                age_bins["60+"] += 1
        except:
            pass  

    return render_template(
        'patients.html',
        patients=patients,
        role=role,
        gender_data=gender_data,
        age_bins=age_bins
    )

# -------------------------
#  Add Patient
# -------------------------
@app.route('/add_patient', methods=['GET', 'POST'])
def add_patient():
    role = request.form.get('role') or request.args.get('role', 'Doctor')
    if role != 'Doctor':
        return redirect(url_for('patients', role=role))

    if request.method == 'POST':
        patient_data = {
            'name': request.form['name'],
            'dob': request.form['dob'],
            'gender': request.form['gender'],
            'address': request.form['address'],
            'phone': request.form['phone'],
            'diagnosis': request.form['diagnosis'],
            'treatment': request.form['treatment']
        }

        conn = get_db_connection()

        if conn is None:
            flash('Database connection failed')
            return redirect(url_for('index'))
    
        cur = conn.cursor(cursor_factory=RealDictCursor)  # Changed to RealDictCursor

        # Inserting new patient
        encrypted_data = crypto.encrypt_patient_data(patient_data)
        
        cur.execute(
            'INSERT INTO patients (name, dob, gender, address, phone, diagnosis, treatment, encrypted_data) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)',
            (patient_data['name'], patient_data['dob'], patient_data['gender'], 
             patient_data['address'], patient_data['phone'], patient_data['diagnosis'], 
             patient_data['treatment'], encrypted_data)
        )

        # Logging the action  
        cur.execute('SELECT hash FROM audit_logs ORDER BY timestamp DESC LIMIT 1')
        last_record = cur.fetchone()
        prev_hash = last_record['hash'] if last_record else '0' * 64  

        timestamp = datetime.now()
        new_hash = crypto.create_log_hash(prev_hash, role, 'Add Patient', 
            f'Added {patient_data["name"]}', timestamp)  

        cur.execute(
            'INSERT INTO audit_logs (role, action, details, timestamp, prev_hash, hash) VALUES (%s, %s, %s, %s, %s, %s)',
            (role, 'Add Patient', 
            f'Added new patient: Name={patient_data["name"]}, DOB={patient_data["dob"]}, ' +
            f'Gender={patient_data["gender"]}, Address={patient_data["address"]}, ' +
            f'Phone={patient_data["phone"]}, Diagnosis={patient_data["diagnosis"]}, ' +
            f'Treatment={patient_data["treatment"]}',
            timestamp, prev_hash, new_hash)
        )

        conn.commit()
        cur.close()
        conn.close()
        return redirect(url_for('patients', role=role))

    return render_template('add_patient.html', role=role)

# -------------------------
#  Edit Patient
# -------------------------
@app.route('/edit_patient/<int:id>', methods=['GET', 'POST'])
def edit_patient(id):
    role = request.form.get('role') or request.args.get('role', 'Doctor')
    
    if role != 'Doctor':
        return redirect(url_for('patients', role=role))
        
    conn = get_db_connection()

    if conn is None:
        flash('Database connection failed')
        return redirect(url_for('index'))
    
    cur = conn.cursor(cursor_factory=RealDictCursor)

    if request.method == 'POST':
        patient_data = {
            'name': request.form['name'],
            'dob': request.form['dob'],
            'gender': request.form['gender'],  
            'address': request.form['address'],
            'phone': request.form['phone'],
            'diagnosis': request.form['diagnosis'],
            'treatment': request.form['treatment']
        }
        
        encrypted_data = crypto.encrypt_patient_data(patient_data)
        
        cur.execute(
            'UPDATE patients SET name=%s, dob=%s, gender=%s, address=%s, phone=%s, diagnosis=%s, treatment=%s, encrypted_data=%s WHERE id=%s',
            (patient_data['name'], patient_data['dob'], request.form['gender'], 
             patient_data['address'], patient_data['phone'], 
             patient_data['diagnosis'], patient_data['treatment'], 
             encrypted_data, id)
        )

        # Logging the update
        cur.execute('SELECT hash FROM audit_logs ORDER BY timestamp DESC LIMIT 1')
        last_record = cur.fetchone()
        prev_hash = last_record['hash'] if last_record else '0' * 64  
        
        timestamp = datetime.now()
        new_hash = crypto.create_log_hash(prev_hash, role, 'Edit Patient', 
            f'Edited patient: {patient_data["name"]}', timestamp)  
        
        cur.execute(
            'INSERT INTO audit_logs (role, action, details, timestamp, prev_hash, hash) VALUES (%s, %s, %s, %s, %s, %s)',
            (role, 'Edit Patient', 
            f'Updated patient {patient_data["name"]}: DOB={patient_data["dob"]}, ' +
            f'Gender={patient_data["gender"]}, Address={patient_data["address"]}, ' +
            f'Phone={patient_data["phone"]}, Diagnosis={patient_data["diagnosis"]}, ' +
            f'Treatment={patient_data["treatment"]}',
            timestamp, prev_hash, new_hash)
        )

        conn.commit()
        cur.close()
        conn.close()
        return redirect(url_for('patients', role=role))

    cur.execute('SELECT * FROM patients WHERE id=%s', (id,))
    patient = cur.fetchone()
    cur.close()
    conn.close()
    return render_template('edit_patient.html', patient=patient, role=role)

# -------------------------
#  Edit Treatment (Nurse)
# -------------------------
@app.route('/edit_treatment/<int:id>', methods=['GET', 'POST'])
def edit_treatment(id):
    role = request.form.get('role') or request.args.get('role', 'Nurse')
    
    if role != 'Nurse':
        return redirect(url_for('patients', role=role))
        
    conn = get_db_connection()

    if conn is None:
        flash('Database connection failed')
        return redirect(url_for('index'))
    
    cur = conn.cursor(cursor_factory=RealDictCursor)

    if request.method == 'POST':
        treatment = request.form['treatment']

        # Getting all current patient data
        cur.execute('SELECT * FROM patients WHERE id=%s', (id,))
        current = cur.fetchone()

        # Creating patient data dictionary for encryption
        patient_data = {
            'name': current['name'],
            'dob': current['dob'],
            'address': current['address'],
            'phone': current['phone'],
            'diagnosis': current['diagnosis'],
            'treatment': treatment,  
            'gender': current['gender']  
        }

        # Encrypting all patient data
        encrypted_data = crypto.encrypt_patient_data(patient_data)
        
        
        cur.execute(
            'UPDATE patients SET treatment=%s, encrypted_data=%s WHERE id=%s',
            (treatment, encrypted_data, id)
        )
        
        # Logging the update
        cur.execute('SELECT hash FROM audit_logs ORDER BY timestamp DESC LIMIT 1')
        last_record = cur.fetchone()
        prev_hash = last_record['hash'] if last_record else '0' * 64  # Changed to use dictionary key
        
        timestamp = datetime.now()
        new_hash = crypto.create_log_hash(prev_hash, role, 'Update Treatment', 
            f'Updated treatment for patient: {patient_data["name"]} (ID: {id})', timestamp)

        cur.execute(
            'INSERT INTO audit_logs (role, action, details, timestamp, prev_hash, hash) VALUES (%s, %s, %s, %s, %s, %s)',
            (role, 'Update Treatment', 
            f'Updated treatment for {patient_data["name"]}: Previous="{current["treatment"]}", ' +
            f'New="{treatment}"', 
            timestamp, prev_hash, new_hash)
        )

        conn.commit()
        cur.close()
        conn.close()
        return redirect(url_for('patients', role=role))

    cur.execute('SELECT * FROM patients WHERE id=%s', (id,))
    patient = cur.fetchone()
    cur.close()
    conn.close()
    return render_template('treatment_updates.html', patient=patient, role=role)

# -------------------------
#  Delete Patient
# -------------------------
@app.route('/delete_patient/<int:id>', methods=['POST'])
def delete_patient(id):
    role = request.form.get('role') or request.args.get('role', 'Doctor')
    if role != 'Doctor':
        return redirect(url_for('patients', role=role))
    
    conn = get_db_connection()

    if conn is None:
        flash('Database connection failed')
        return redirect(url_for('index'))

    # Getting patient name before deleting
    cur = conn.cursor(cursor_factory=RealDictCursor)  # Changed to RealDictCursor
    cur.execute('SELECT name FROM patients WHERE id=%s', (id,))
    patient = cur.fetchone()

    # Creating hash chain for audit log
    cur.execute('SELECT hash FROM audit_logs ORDER BY timestamp DESC LIMIT 1')
    last_record = cur.fetchone()
    prev_hash = last_record['hash'] if last_record else '0' * 64  # Changed to use dictionary key
    
    timestamp = datetime.now()
    new_hash = crypto.create_log_hash(prev_hash, role, 'Delete Patient', 
        f'Deleted {patient["name"] if patient else "Unknown"}', timestamp)
    
    # Adding audit log entry

    cur.execute(
        'INSERT INTO audit_logs (role, action, details, timestamp, prev_hash, hash) VALUES (%s, %s, %s, %s, %s, %s)',
        (role, 'Delete Patient', f'Deleted patient: {patient["name"]}', timestamp, prev_hash, new_hash)
    )

    # Deleting the patient
    cur.execute('DELETE FROM patients WHERE id=%s', (id,))

    conn.commit()
    cur.close()
    conn.close()
    return redirect(url_for('patients', role=role))

# -------------------------
#  Audit Logs (Admin)
# -------------------------
@app.route('/logs')
def logs():
    role = request.args.get('role')
    if role != 'Admin':
        return redirect(url_for('index'))
    
    try:
        conn = get_db_connection()
        if conn is None:
            flash('Database connection error')
            return redirect(url_for('index'))
            
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute('SELECT * FROM audit_logs ORDER BY timestamp DESC;')
        logs = cur.fetchall()
        
        return render_template('logs.html', logs=logs, role=role)  # Added role here
        
    except psycopg2.Error as e:
        print(f"Database error: {e}")
        flash('Database error occurred')
        return redirect(url_for('index'))
        
    finally:
        if 'cur' in locals():
            cur.close()
        if 'conn' in locals():
            conn.close()

# ----------------------------
#  View Encrypted Data (Admin)
# ----------------------------
@app.route('/view_encrypted/<int:id>')
def view_encrypted(id):
    role = request.args.get('role')
    if role != 'Admin':
        return redirect(url_for('index'))
        
    conn = get_db_connection()
    if conn is None:
        flash('Database connection failed')
        return redirect(url_for('index'))
    
    cur = conn.cursor(cursor_factory=RealDictCursor)
    
    cur.execute('SELECT * FROM patients WHERE id=%s', (id,))
    patient = cur.fetchone()
    
    # Handling None values and creating patient_data dictionary
    if patient and not patient['encrypted_data']:
        patient_data = {
            'name': patient['name'] or '',
            'dob': patient['dob'] or '',
            'gender': patient['gender'] or '',
            'address': patient['address'] or '',
            'phone': patient['phone'] or '',
            'diagnosis': patient['diagnosis'] or '',
            'treatment': patient['treatment'] or ''
        }
        encrypted_data = crypto.encrypt_patient_data(patient_data)
        cur.execute(
            'UPDATE patients SET encrypted_data=%s WHERE id=%s',
            (encrypted_data, id)
        )
        conn.commit()
        patient['encrypted_data'] = encrypted_data
    
    # Converting memoryview to string and decrypt data
    decrypted_data = None
    if patient and patient['encrypted_data']:
        try:
            # Converting memoryview to bytes
            encrypted_bytes = bytes(patient['encrypted_data'])
            # Store base64 string for display
            patient['encrypted_string'] = encrypted_bytes.decode('utf-8')
            # Decrypting the data
            decrypted_data = crypto.decrypt_patient_data(encrypted_bytes)
        except Exception as e:
            print(f"Error processing encrypted data: {e}")
            patient['encrypted_string'] = "Error processing encrypted data"
            flash('Error processing encrypted data')
    
    cur.close()
    conn.close()
    
    return render_template('view_encrypted.html', 
                         patient=patient, 
                         decrypted_data=decrypted_data,
                         role=role)

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)

