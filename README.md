# Go Auth Service

## Environment
- `DATABASE_URI`
- `DATABASE_NAME`
- `TOKEN_SECRET_KEY`
- `TOKEN_EXPIRATION_IN_MINUTES`
- `REFRESH_TOKEN_EXPIRATION_IN_HOURS`
- `BASE_URL`
- `FRONTEND_URL` (optional, used in welcome email)
- `BREVO_API_URL`
- `BREVO_API_KEY`
- `SUPPORT_EMAIL`
- `MAILER_SOURCE_NAME`

## Endpoints
- `POST /auth/signIn`
- `POST /auth/refreshToken`
- `POST /auth/logout`
- `POST /auth/signUp/email`
- `POST /auth/signUp/otp`
- `POST /auth/signUp/personal-details`
- `POST /auth/reset-password/email`
- `POST /auth/reset-password/otp`
- `POST /auth/reset-password`
- `GET /auth/me` (protected)
- Swagger UI: `http://localhost:8080/swagger/index.html`

## Examples

### Sign in
```bash
curl -X POST http://localhost:8080/auth/signIn \
  -H "Content-Type: application/json" \
  -d '{"username":"user@example.com","password":"secret"}'
```

### Refresh token
```bash
curl -X POST http://localhost:8080/auth/refreshToken \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refresh-token>"}'
```

### Logout
```bash
curl -X POST http://localhost:8080/auth/logout \
  -H "Content-Type: application/json" \
  -d '{"refreshToken":"<refresh-token>"}'
```

### Registration flow
```bash
curl -X POST http://localhost:8080/auth/signUp/email \
  -H "Content-Type: application/json" \
  -d '{"firstname":"Ada","lastname":"Lovelace","email":"ada@example.com"}'
```

```bash
curl -X POST http://localhost:8080/auth/signUp/otp \
  -H "Content-Type: application/json" \
  -d '{"email":"ada@example.com","code":"123456"}'
```

```bash
curl -X POST http://localhost:8080/auth/signUp/personal-details \
  -H "Content-Type: application/json" \
  -d '{"email":"ada@example.com","password":"secret","passwordConfirmation":"secret"}'
```

### Reset password flow
```bash
curl -X POST http://localhost:8080/auth/reset-password/email \
  -H "Content-Type: application/json" \
  -d '{"email":"ada@example.com"}'
```

```bash
curl -X POST http://localhost:8080/auth/reset-password/otp \
  -H "Content-Type: application/json" \
  -d '{"email":"ada@example.com","code":"123456"}'
```

```bash
curl -X POST http://localhost:8080/auth/reset-password \
  -H "Content-Type: application/json" \
  -d '{"email":"ada@example.com","password":"newsecret","passwordConfirmation":"newsecret"}'
```

### Protected route
```bash
curl http://localhost:8080/auth/me \
  -H "Authorization: Bearer <access-token>"
```
