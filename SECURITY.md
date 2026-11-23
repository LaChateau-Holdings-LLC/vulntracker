# Security policy

## Report a security issue

For a flaw in Vulnerability Tracker, use **Security → Report a vulnerability**
on GitHub if private reporting is available. Otherwise contact the repository
owner through an established private channel. Include the affected version,
impact, and enough detail to reproduce the issue with synthetic data. Keep
credentials, customer records, and sensitive evidence out of public issues.

For an issue with a particular deployment or an advisory stored in the
tracker, contact that deployment's operator.

## Deploy and operate securely

- Put shared deployments behind an HTTPS reverse proxy. Keep the container
  listener on a private interface or internal network.
- The default `off` mode and OIDC `test` mode allow unauthenticated access.
  Use them on a trusted network during setup. Switch to
  `TRACKER_AUTH_MODE=required` after verifying provider sign-in.
- For shared access, configure an allowed claim value and a distinct admin
  claim value. Members can modify tracker records. The admin value also
  grants access to branding settings.
- Keep the OIDC client secret and local `.env` outside source control and
  restrict access to both. Redact authorization codes, cookies, and
  credentials from reverse-proxy logs.
- Protect the SQLite volume, backups, and exported reports. They may
  contain non-public vulnerability and inventory records. Apply software
  updates and verify backups before upgrades.

The tracker records advisories and mitigation decisions entered by its
operators. The current release provides manual entry and optional inventory.
