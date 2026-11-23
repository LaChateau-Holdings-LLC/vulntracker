# Vulnerability Tracker

A manual tracker with a reusable product list and persistent SQLite storage.

## Run locally

Run `python3 app.py` or `docker compose up --build -d`, then open
[the tracker](http://localhost:8080). The Python command stores records in
`data/tracker.sqlite3`. Docker Compose stores records in the `tracker-data`
named volume.

The app binds to localhost by default and has no built-in authentication.
Keep that binding for local use, or put the service behind an authenticated
reverse proxy before making it available to other users.

## Record a vulnerability

Choose **Add vulnerability**, add any missing products, and select every
affected product. Enter a title, disclosure date, and any available CVE,
vendor reference, notes, and links. Use **View** and **Edit vulnerability**
to record mitigation. Checking **Mitigated** requires a date and an
explanation of the action taken.

The list can be searched by title, CVE, vendor reference, or product name.
Use the product and status filters to narrow the results. Mitigation status
applies to the vulnerability as a whole.

## Operations

Use `docker compose ps` to check service status and
`docker compose logs tracker` to view application logs. Run
`docker compose up --build -d` after updating the source. A regular
`docker compose down` preserves the named data volume. The `-v` flag
removes that volume and its records.

See [architecture decisions](DECISIONS.md), [the roadmap](ROADMAP.md),
and [contributor guidance](AGENTS.md).
