# ThreatLens Defensive Security & Hardening Guide

ThreatLens is engineered with defense-in-depth principles for security monitoring environments:

## Security Safeguards

1. **Defensive Monitoring Scope Only**:
   - ThreatLens contains no offensive exploitation, credential harvesting, persistence, or automated destructive response tooling. All test scenarios utilize synthetic demo logs.
2. **Untrusted Telemetry Handling**:
   - Ingested log messages, IOC descriptions, and external payloads are sanitized.
   - Credentials, passwords, bearer tokens, and credit card numbers are automatically masked via regex redaction filters before persistence.
3. **SQL Injection Prevention**:
   - All database queries use SQLAlchemy 2.0 parameterized expressions and ORM statements. No raw user strings are concatenated into SQL statements.
4. **Authentication & Access Control**:
   - Passwords hashed using bcrypt with dynamic salts.
   - JWT tokens signed with HS256 and configurable expiration windows.
   - Role-Based Access Control (`admin`, `analyst`, `readonly`) restricting sensitive configuration endpoints (e.g. enabling/disabling detection rules).
5. **CORS & Network Boundaries**:
   - Explicit origin whitelisting via `CORS_ORIGINS` environment setting.
   - Non-root container execution (`USER threatlens` in Dockerfile).
   - Global exception handling preventing internal database error details and stack traces from leaking to API clients.
6. **Rate Limiting & Memory Protection**:
   - Payload size caps (default 10 MB per request).
   - Bounded batch ingestion limits (up to 2,000 records per batch).
   - Bounded queue concurrency preventing unbounded memory exhaustion.

