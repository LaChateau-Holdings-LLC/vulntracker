# Roadmap

## Initial release

- [x] Add and reuse products when recording an advisory.
- [x] View and edit advisories, identifiers, disclosure dates, notes, and links.
- [x] Track mitigation status, date, and action taken.
- [x] Search advisories and filter by product or status.
- [x] Persist records across service restarts using SQLite.

## Inventory and reporting

- [x] Track optional quantities by product and running version.
- [x] Print or save a report with selectable counts, date range, and list sorting.

## Managed network inventory discovery

- [ ] Let operators configure authorized network ranges and reference read-only SNMP or SSH credentials stored separately from inventory records.
- [ ] Collect vendor, model, running version, and a stable device identifier where available. Record when each device was last seen and show collection failures.
- [ ] Match observations to the shared catalog and update inventory quantities by product and version. Deduplicate devices across scans, preserve manually managed entries, and flag ambiguous matches for review.
- [ ] Make discovered products available in the existing **Affected hardware or software** selector when an operator records a vulnerability. Show known running versions to help the operator decide which products to link.

## Potential follow-up work

- Add product renaming and archiving while retaining existing associations.
- Add data export and verify a documented database backup and restore workflow.
- Add per-product mitigation tracking if products are remediated independently.
- Evaluate an audit history for multi-user deployments.
