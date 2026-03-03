# go-better-auth – Working Example

A self-contained backend example that integrates **go-better-auth** with a real
PostgreSQL database.  Everything runs locally via Docker Compose.

## Prerequisites

- [Docker](https://docs.docker.com/get-docker/) + [Docker Compose](https://docs.docker.com/compose/)
- (optional) Go 1.24+ if you want to run the backend outside Docker

---

## Quick start with Docker Compose

```bash
# From the repo root
cd examples

docker compose up --build
```

Docker Compose will:

1. Start a **PostgreSQL 16** instance on `localhost:5432` and apply
   `db/init.sql` (creates all required tables).
2. Build and start the **Go backend** on `localhost:8080`.

---

## Trying it out

Once the stack is up, use curl (or any HTTP client) to exercise the auth API.

### Sign up

```bash
curl -s -X POST http://localhost:8080/api/auth/sign-up/email \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"supersecret","name":"Alice"}' | jq .
```

### Sign in

```bash
curl -s -c cookies.txt -X POST http://localhost:8080/api/auth/sign-in/email \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.com","password":"supersecret"}' | jq .
```

### Get current session

```bash
curl -s -b cookies.txt http://localhost:8080/api/auth/get-session | jq .
```

### Sign out

```bash
curl -s -b cookies.txt -c cookies.txt -X POST http://localhost:8080/api/auth/sign-out | jq .
```

### Other endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/sign-up/email` | Register with email + password |
| `POST` | `/api/auth/sign-in/email` | Sign in, receive a session cookie |
| `POST` | `/api/auth/sign-out` | Revoke current session |
| `GET`  | `/api/auth/get-session` | Return current user + session |
| `GET`  | `/api/auth/list-sessions` | List all active sessions for user |
| `POST` | `/api/auth/revoke-session` | Revoke a specific session |
| `POST` | `/api/auth/change-password` | Change password (authenticated) |
| `POST` | `/api/auth/request-password-reset` | Initiate password-reset flow |
| `POST` | `/api/auth/reset-password` | Complete password reset with token |
| `POST` | `/api/auth/update-user` | Update name / image |
| `POST` | `/api/auth/delete-user` | Delete account |
| `GET`  | `/health` | Health check |

---

## Running locally (without Docker)

1. Start Postgres:

   ```bash
   docker compose up postgres -d
   ```

2. Apply the schema:

   ```bash
   psql "postgres://auth:auth@localhost:5432/authdb" -f db/init.sql
   ```

3. Run the backend:

   ```bash
   cd examples/backend
   cp .env.example .env   # edit if needed
   go run .
   ```

---

## Project layout

```
examples/
├── docker-compose.yml          # Postgres + backend services
├── db/
│   └── init.sql                # Database schema (auto-applied by Postgres on first start)
├── backend/
│   ├── main.go                 # HTTP server wiring go-better-auth to Postgres
│   ├── go.mod                  # Standalone Go module
│   ├── Dockerfile              # Multi-stage image (build context = repo root)
│   ├── .env.example            # Environment variable reference
│   └── adapter/
│       └── postgres/
│           └── postgres.go     # adapter.Adapter implementation for PostgreSQL
└── README.md
```

## How it works

```
HTTP request
    │
    ▼
net/http mux  ──/api/auth/──►  betterauth.Auth.Handler()
                                        │
                                        ▼
                               adapter.Adapter interface
                                        │
                                        ▼
                               examples/backend/adapter/postgres
                                        │
                                        ▼
                                   PostgreSQL 16
```

The Postgres adapter translates the library's generic `adapter.Query` (with
`Where`, `Limit`, `SortBy`, …) into parameterised SQL using the `pgx/v5`
driver.  Column names are the same snake_case identifiers that the betterauth
internal layer already uses (`user_id`, `created_at`, etc.), so no mapping
layer is required.

## Frontend

Any frontend that works with the original
[better-auth](https://www.better-auth.com) TypeScript library is compatible
with this backend – the HTTP API and cookie behaviour are identical.
