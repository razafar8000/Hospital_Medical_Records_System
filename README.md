# Hospital Medical Records System

A **secure, containerized medical records management system** built with **Flask** and **PostgreSQL**, featuring enterprise-grade encryption, role-based access control, and tamper-evident audit logging designed for real-world healthcare environments.

---

## Features

- **Role-Based Access Control (RBAC):** Doctors, Nurses, and Admins each have distinct permissions to ensure least-privilege access.
- **End-to-End Encryption:** Patient data is encrypted using **AES-256-GCM** (via OpenSSL) before being stored in PostgreSQL.
- **Tamper-Evident Audit Logs:** Every action (add, edit, delete) is logged with cryptographic hash chaining to preserve data integrity.
- **Modern UI & Visualizations:** Clean, responsive interface with real-time patient demographics (age and gender distribution).
- **Dockerized for Easy Setup:** One command launches both the Flask app and PostgreSQL database using Docker Compose.

---

## Quick Start (Docker)

Requires [Docker](https://docs.docker.com/get-docker/) installed.

```bash
# Clone this repository
git clone https://github.com/<your-username>/Hospital_Medical_Records_System.git
cd Hospital_Medical_Records_System

# Build and run containers
docker compose up --build

```

Then open [http://localhost:5000](http://localhost:5000) in your browser.

## Technology Stack

- **Backend:** Flask (Python)  
- **Database:** PostgreSQL 15  
- **Encryption:** OpenSSL with `cryptography` library (AES-256-GCM)  
- **Containerization:** Docker & Docker Compose  
- **Frontend:** HTML5, CSS3, Jinja2 Templates  
- **Icons:** Font Awesome  
- **Charts:** Chart.js for data visualization  

---

## Project Structure

```plaintext
Hospital_Medical_Records_System/
├── app.py                   # Main Flask application
├── crypto_utils.py          # Encryption utilities
├── docker-compose.yml       # Docker orchestration
├── Dockerfile               # Container configuration
├── requirements.txt         # Python dependencies
├── init.sql                 # Database schema & sample data
├── templates/               # HTML templates
│   ├── index.html           # Role selection page
│   ├── patients.html        # Patient dashboard
│   ├── add_patient.html     # New patient form
│   ├── edit_patient.html    # Edit patient form
│   ├── treatment_updates.html # Nurse interface
│   ├── view_encrypted.html  # Admin encryption view
│   └── logs.html            # Audit log viewer
└── static/                  # CSS, JS, and assets
```
## Security Considerations

- **AES-256-GCM** used for confidentiality and integrity of patient data.  
- **RBAC (Role-Based Access Control)** enforces least-privilege access for Doctors, Nurses, and Admins.  
- **Audit Logs** are chained with SHA-256 hashes to make any tampering evident.  
- **Database credentials and encryption keys** are configurable via environment variables for secure deployment.



