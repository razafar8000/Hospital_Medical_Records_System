-- Create patients table
CREATE TABLE IF NOT EXISTS patients (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    dob DATE NOT NULL,
    gender VARCHAR(10) NOT NULL,
    address TEXT,
    phone VARCHAR(20),
    diagnosis TEXT NOT NULL,
    treatment TEXT NOT NULL,
    encrypted_data BYTEA
);

-- Create audit_logs table
CREATE TABLE IF NOT EXISTS audit_logs (
    id SERIAL PRIMARY KEY,
    role VARCHAR(20) NOT NULL,
    action VARCHAR(50) NOT NULL,
    details TEXT NOT NULL,
    timestamp TIMESTAMP NOT NULL,
    prev_hash VARCHAR(64) NOT NULL,
    hash VARCHAR(64) NOT NULL
);