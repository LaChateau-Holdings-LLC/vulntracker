# Architecture decisions

## 001. Manual advisory tracking

The initial release uses a reusable product catalog and manual vulnerability
entry. A record can refer to several products. A title, disclosure date, and
at least one product are required. CVE and vendor advisory IDs are optional
so advisories without either identifier can still be tracked.

## 002. Mitigation belongs to the vulnerability record

The initial workflow uses open and mitigated states. A mitigated record
requires the date and a description of the action taken. The status applies
to all products associated with the record. Product-specific remediation
would require a separate status and details on each affected-product entry.

## 003. SQLite and a single application service

Use Python's standard library and SQLite to keep the application deployable
as a single container. Store the database in a named volume. A join table
connects vulnerabilities and products through foreign keys, and a transaction
keeps the record and its product selection consistent.

## 004. Private access by default

Docker Compose publishes the port on loopback. The container runs as a
non-root user. Deployments serving other users require an authenticated
reverse proxy or an application authentication layer. The repository contains
application code and documentation. Operational records live in SQLite.
