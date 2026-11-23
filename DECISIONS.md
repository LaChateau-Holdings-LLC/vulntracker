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

## 005. Optional inventory by product and running version

The advisory workflow uses the shared product catalog even when inventory
is empty. Inventory records hold an aggregate quantity for each product and
version. An unspecified version supports model-level counts. This avoids
requiring a record for each installation and leaves the advisory status
independent of inventory quantities and versions.

## 006. Browser-generated PDF reports

Build a print layout from the selected disclosure dates and sections and
use the browser's print dialog for paper and PDF output. The report reflects
the current mitigation status of the matching records. Its overall totals
count records, while product counts use the product associations.

## 007. Classify the shared catalog as hardware or software

Hardware and software share the same catalog and can both be linked to a
vulnerability or inventoried by version. Existing items stay unclassified
until someone selects a type. Classification retains the catalog ID and all
existing associations.

## 008. Use the management tools' workspace layout

Vulnerabilities, Product inventory, and Reports have separate work areas
in the same application shell. The Website Management tool informed the
section headings and panel layout. The TV Management tool informed the
dark navigation rail, which becomes a compact menu on smaller screens.

## 009. Instance branding and report identity

Store the application name, organization, and uploaded images in SQLite
alongside the tracker data. Images use same-origin endpoints. The report
header uses the same branding as the workspace, with print styles for
the header, metrics, and tables.

## 010. Guided OIDC setup and explicit enforcement

Configure the provider and its credential through the deployment environment.
The Settings guide covers single-tenant Entra registration and generic
provider discovery. Test mode verifies an account and role before the
operator turns on required sign-in. Both modes use authorization code with
PKCE, validated ID tokens, and server-side sessions. Required mode protects
tracker data and enforces the configured branding administrator role.
