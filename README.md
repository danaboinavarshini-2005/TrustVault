# TrustVault

### Secure Document Sharing with a Real Audit Trail

TrustVault is a Django-based document management and sharing application developed for the Snovasys Fresher Hiring Challenge 2026.

It demonstrates role-based access control, document sharing, permission revocation, and audit logging.

## Features

* User authentication
* Administrator, Owner, and Viewer roles
* Document upload and management
* Document search and filtering
* Read and Edit permissions
* Grant and revoke document access
* Authorization checks on document operations
* Audit logging for selected activities
* Administrator activity dashboard
* Automated security and permission tests

## Technology Stack

* Python
* Django
* SQLite for local development
* HTML and CSS

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/danaboinavarshini-2005/TrustVault.git
cd TrustVault
```

### 2. Create and activate a virtual environment

On Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

### 3. Install dependencies

```powershell
python -m pip install -r requirements.txt
```

### 4. Apply database migrations

```powershell
python manage.py migrate
```

### 5. Create an administrator account

```powershell
python manage.py createsuperuser
```

Follow the prompts to create your account.

### 6. Start the development server

```powershell
python manage.py runserver
```

Open `http://127.0.0.1:8000/` to access TrustVault.

To access Django Admin, open `http://127.0.0.1:8000/admin/`.

## Running Tests

Run the automated tests with:

```powershell
python manage.py test documents
```

## Security Notes

* Access to documents is controlled by application permissions.
* Unauthorized document operations are restricted.
* Selected activities are recorded in the audit log.
* SQLite is intended for local development in this project.
* Before production deployment, configure secure settings, HTTPS, appropriate database access, and secret management.

## Project Repository

GitHub: https://github.com/danaboinavarshini-2005/TrustVault
