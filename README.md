# auth-project-SMIT



Secure async authentication backend built with FastAPI, JWT, PostgreSQL, and Redis.

Features:

* JWT Authentication
* Access & Refresh Tokens
* Redis Token Blacklisting
* Logout Revocation
* Protected Routes
* Password Hashing
* Async FastAPI Architecture
* Redis via Docker

Routes:

```text id="srt1"
POST /auth/register
POST /auth/login
POST /auth/refresh
POST /auth/logout
GET  /users/me
GET  /health
```

Run Project:

```bash id="srt2"
pip install -r requirements.txt
docker run -d -p 6379:6379 redis
uvicorn app.main:app --reload
```
