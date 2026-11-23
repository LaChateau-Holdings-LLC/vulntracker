# Working on Vulnerability Tracker

This application is a manual vulnerability and mitigation register. It uses
Python 3.12, SQLite, and browser-native HTML, CSS, and JavaScript.

- `app.py` serves the interface and JSON API and owns schema and validation.
- `tracker_auth.py` handles OIDC provider configuration, token validation, and sessions.
- `static/` contains the browser interface.
- `compose.yaml` pulls the release image. `Dockerfile` and `compose.build.yaml` support local builds.
- `DECISIONS.md` records design choices. `ROADMAP.md` records planned work.

Keep schema changes compatible with existing databases. Use a migration when
changing the existing schema, and keep vulnerability writes and affected
product updates in one transaction. Add or update server-side validation when
changing what a form accepts.

Use synthetic records for development and verification. Keep live vulnerability
data, SQLite files, credentials, and backups outside version control. Use a
temporary database for smoke checks.

Validate source and deployment configuration with:

```sh
python3 -m py_compile app.py tracker_auth.py
node --check static/app.js
node --check static/login.js
docker compose config --quiet
```

For changes to data entry, exercise the corresponding UI or API flow against
a temporary database. Check that a record with multiple products can be saved,
edited, and read after a restart. For deployment changes, verify the service
responds on the configured port and retains its named volume.
