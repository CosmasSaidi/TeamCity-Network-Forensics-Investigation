# Screenshot Preservation Notes

- Generated: 2026-11-05T18:29:05Z (UTC).
- Collection directory: source screenshot collection (local absolute path omitted for publication).
- Working output directory: `evidence/` (relative to the repository root).
- Expected screenshot count: **70**.
- Verified screenshot count: **70** regular files.
- SHA-256 hashes generated successfully: **70/70**.
- Hash algorithm: **SHA-256**, calculated over each entire original file.
- Evidence IDs: **EV-001 through EV-070**, assigned in chronological filename order.
- First screenshot: `Screenshot From 2026-11-03 00-54-22.png`.
- Last screenshot: `Screenshot From 2026-11-04 21-24-13.png`.
- Count, endpoint, file-type or unexpected-entry discrepancies: **None detected**.
- Hashing errors: **None**.
- Evidence size or modification metadata changes detected during hashing: **None**.

## Selection and metadata

All entries matching `Screenshot From YYYY-MM-DD HH-MM-SS.png` within the inclusive filename range above were included. Filename dates and times were parsed as local, timezone-unspecified screenshot labels and checked as valid calendar timestamps. No other screenshot files were included. The CSV preserves ascending chronological filename order.

File sizes and modification timestamps come directly from filesystem metadata. Modification timestamps are written in UTC with the recorded nanosecond precision and a `Z` suffix. Filesystem modification times are not assumed to be screenshot creation times or captured network-event times.

The original files were opened read-only and hashed in place. O_NOATIME was used for 70/70 reads to avoid access-time updates. File identity, size, modification time and change time were compared before and after hashing. No original screenshots were modified, renamed, moved, deleted, compressed, copied or uploaded. No screenshot-content review was performed in this phase.

The public manifest contains only evidence IDs, filenames, collection-relative paths, sizes, SHA-256 hashes and modification timestamps. It contains no extracted credentials, passwords or authentication tokens.

## Outputs and scope

- `SCREENSHOT_MANIFEST.csv`: one metadata and hash record for each original screenshot.
- `PRESERVATION_NOTES.md`: this count, selection and processing summary.

This documents the local inventory and hashing operation. It does not establish or claim a formal chain of custody, prior provenance or authenticity of the screenshots.

## Publication metadata cleanup — 2026-11-07

Local absolute paths and account metadata were omitted from the public manifest and report; collection-relative filenames retain the original evidence relationships. Original screenshots, evidence IDs, original SHA-256 values, sizes and timestamps remain unchanged. Earlier QA document hashes refer to the pre-cleanup snapshot. The F-001 presentation-only mask and revised derivative hash are recorded in [DERIVATIVE_MANIFEST.csv](../report/figures/DERIVATIVE_MANIFEST.csv); its original source hash is unchanged.
