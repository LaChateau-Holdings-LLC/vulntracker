# Roadmap

## Initial release

- [x] Add and reuse products when recording an advisory.
- [x] View and edit advisories, identifiers, disclosure dates, notes, and links.
- [x] Track mitigation status, date, and action taken.
- [x] Search advisories and filter by product or status.
- [x] Persist records across service restarts using SQLite.

## Potential follow-up work

- Add product renaming and archiving while retaining existing associations.
- Add data export and verify a documented database backup and restore workflow.
- Add per-product mitigation tracking if products are remediated independently.
- Evaluate authentication and an audit history if the tracker becomes shared.
