# Cybersecurity Secure API

A security-focused multi-tenant REST API built with **FastAPI, SQLite, SQLAlchemy, Argon2id, opaque bearer-token sessions, and Pytest**.

## Features

- Argon2id password hashing; plaintext passwords are never stored.
- Random opaque bearer tokens; only SHA-256 token digests are stored.
- Configurable session expiration and server-side logout revocation.
- Public registration always creates the `user` role.
- Admin privileges are provisioned only through a local CLI script.
- Record ownership is derived from the authenticated identity.
- Owners can read their own records; administrators can read across tenants.
- Unauthorized and nonexistent records both return 404.
- Per-account lockout after five failed attempts for 15 minutes.
- Strict Pydantic request models reject unexpected fields.
- Request body size is capped at 16 KB.
- Audit events avoid passwords, raw tokens, authorization headers, and record bodies.

## Requirements

- Python 3.10+
- pip

## Windows setup (PowerShell)

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements-dev.txt
Copy-Item .env.example .env
uvicorn app.main:app --reload
```

If PowerShell blocks activation for this terminal, run:
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\.venv\Scripts\Activate.ps1
```

API: http://127.0.0.1:8000  
Docs: http://127.0.0.1:8000/docs  
Health: http://127.0.0.1:8000/health

## Linux/macOS setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
uvicorn app.main:app --reload
```

## API

| Method | Endpoint | Authentication | Purpose |
|---|---|---|---|
| POST | `/register` | No | Register a normal user |
| POST | `/login` | No | Create a bearer session |
| POST | `/logout` | Yes | Revoke current session |
| POST | `/records` | Yes | Create a private record |
| GET | `/records/{record_id}` | Yes | Read own record or admin-accessible record |
| GET | `/` | No | Service status |
| GET | `/health` | No | Database health check |

### Example requests

Register:
```json
{"username":"alice","password":"correct-horse-battery"}
```

Login:
```json
{"username":"alice","password":"correct-horse-battery"}
```

Create a record (use the returned access token):
```json
{"title":"Private note","body":"Only the owner or an administrator can read this."}
```

## Create an administrator

Run from the project root:
```powershell
python -m scripts.create_admin
```
The script prompts for a username and password without echoing the password. It can create a new administrator or promote an existing account. Do not expose this script as an API endpoint.

## Tests

```powershell
python -m pytest -v
```

Verified locally: **8 tests passed** with `python -m pytest -q`. Run the command above to reproduce the result.

## Security design

### Passwords
Argon2id uses a unique random salt for each password. The encoded Argon2 hash (including its parameters and salt) is stored; plaintext passwords are not.

### Sessions
A 256-bit random opaque token is returned once. The database stores only its SHA-256 digest. Every protected request checks the digest and expiry. Logout deletes the server-side session.

### Authorization
The record owner is assigned from the authenticated user, never from client input. A normal user can read only their own records. Admin access is checked server-side. A non-owner receives the same 404 response as a missing record.

### Brute-force resistance
Failed attempts are counted per account. The configured threshold is five and the lockout is 15 minutes. Successful login clears the counter.

### Database and input
SQLAlchemy parameterizes database operations. Pydantic models reject extra fields and enforce field lengths. The ASGI middleware limits complete request bodies to 16 KB.

### Audit logging
Security events include registration, login success/failure, lockout, logout, record creation, denied record reads, and administrator reads. Sensitive credentials and record bodies are not written to logs.

## Threat model

| Threat | Mitigation | Residual risk |
|---|---|---|
| Password database exposure | Argon2id salted password hashes | Weak passwords can still be guessed offline |
| Session database exposure | SHA-256 token digests | A token stolen from a live client remains usable until expiry/revocation |
| Session replay after logout | Server-side session deletion | A stolen active token can be used before revocation |
| Brute-force login | Per-account lockout | Lockout can be abused to deny service to a known account |
| IDOR / BOLA | Owner check on every record read | Authorization bugs must be caught by tests |
| Privilege escalation | Fixed registration role and CLI-only admin provisioning | Host/database administrators can change roles |
| SQL injection | SQLAlchemy parameterized queries | Unsafe raw SQL added later could reintroduce risk |
| Oversized requests | 16 KB body cap and field limits | Reverse proxy should also enforce request limits |

## Assumptions and limitations

- SQLite is suitable for this single-instance assessment prototype; a multi-instance deployment should use PostgreSQL and a shared session/lockout store.
- The API is intended to run behind HTTPS in deployment. Local development uses HTTP.
- Records are not encrypted at rest in this prototype.
- Account lockout is an availability trade-off; production should add edge-level IP rate limiting and account recovery.
- MFA, password reset, breached-password screening, and centralized audit-log storage are outside this prototype's scope.

## Production hardening

Use HTTPS, restrict database file permissions, keep `.env` secrets out of Git, disable interactive API docs in production, use a managed database, add centralized rate limiting, and ship audit events to protected append-only storage.

## Author

Gagan Sai Eashwar  
Cybersecurity | Application Security | API Security

**Project:** Cybersecurity Secure API  
**Purpose:** Cybersecurity Technical Assessment
