# Researchers Management API

A **FastAPI-based backend** for managing researcher profiles, featuring **JWT authentication**, **LDAP integration**, and **automated authority fetching**.


## Features

- **Authentication** - Dual support for Local DB users and LDAP integration
- **Researcher Management** - CRUD operations for: Customers (Researchers), Faculties, Departments
- **Smart Filtering** - Search by: Name, Email, ORCID, Scopus ID, ECRIS ID
- **Authority Logic** - Filtering for researchers with multiple authority identifiers
- **DSpace Integration** - Automatic generation of DSpace name indexes
- **Export** - CSV export of all researcher data

## Tech Stack

- **Framework:** FastAPI  
- **ORM:** SQLAlchemy  
- **Database:** SQLite (default) / PostgreSQL compatible  
- **Authentication:** JWT (JSON Web Tokens) & LDAP  
- **Validation:** Pydantic v2  


## Installation

### 1. Clone the repository

```bash
git clone https://github.com/imilos/researchers-api.git
cd researchers-api
```

### 2. Create and activate a virtual environment:

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install dependencies:

```bash
pip install fastapi uvicorn sqlalchemy pydantic passlib python-multipart PyJWT requests python-ldap fastapi-ldap
```

### 4. Configuration: Ensure you have a `config.py` file in the root directory with the following variables:

- `LDAP_CONFIG`: Configuration for LDAP server.
- `SQLALCHEMY_DATABASE_URL`: Database connection string.
- `ALLOWED_ORIGINS`: List of CORS allowed domains.
- `AUTHORITY_URL`: External API for fetching identifiers.
- `LDAP_DOMAINS`: List of domains for LDAP cleanup.

### 5. Running the Application

Development mode: 
```bash
uvicorn app_fastapi:app --host 0.0.0.0 --port 8000 --reload
```
or Production mode:
```bash
uvicorn app_fastapi:app --host 0.0.0.0 --port 8000
```

## API Documentation

Once the server is running, you can access the interactive documentation:

- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Database Schema

The API manages three main entities:

- **Faculty**: Academic institutions.
- **Department**: Specific units within a faculty.
- **Customer (Researcher)**: Individual profiles linked to faculties/departments with various academic IDs (ORCID, Scopus, ECRIS).
