# TeamCity Investigation — Publication Readiness Audit

Audit date: **2026-11-07**. Overall status: **READY WITH WARNINGS**.

## Overall assessment

The current directory contains the expected portfolio documentation, evidence metadata and seven selected presentation figures. No credential value, private key, temporary output, local environment file, cache, editor-state file, symlink or unexpected executable was identified. Existing documentation links and evidence references resolve, and the reviewed source/figure hash records agree.

The warnings concern **local account/filesystem metadata in three text files**, a small extraneous terminal fragment in Figure F-001, and confirming the configured Git author identity before a future commit. These are publication/privacy considerations, not new incident findings. **Incident severity remains undetermined.** No publication, Git initialization or repository change beyond this requested audit was performed.

This is a readiness assessment of the current directory, not certification of the external raw screenshot collection for public release. The original investigation, original screenshot-content audit and report writing were not repeated. Review of the seven selected figures was limited to sensitive-data/publication inspection.

## Prioritized findings

| Priority | ID | File/location | Finding and recommended disposition |
|---|---|---|---|
| Critical | — | Entire audited directory | None identified. No detected private-key or usable credential exposure requiring an immediate publication block. |
| High | — | Entire audited directory | None identified. The external raw originals are not included in this directory and are not approved by this audit for publication. |
| **Medium** | **PUB-M01** | `evidence/SCREENSHOT_MANIFEST.csv:2–71`, `original_absolute_path` column; `evidence/PRESERVATION_NOTES.md:4–5`; `report/INVESTIGATION_REPORT.md:57` | **73 local account/path occurrences across three files.** Preservation metadata exposes a local account component and filesystem layout. No values are reproduced here. Decide whether that disclosure is acceptable before public release. If it is not, authorize a public sanitization plan while retaining the restricted preservation records and their hashes. Do not silently overwrite preservation evidence or omit the manifest and break documentation links. |
| **Low** | **PUB-L01** | `report/figures/F-001_EV-008.png`, lower-right edge, approximately x=1200–1512/y=728–759 in derivative pixels | A small non-incident terminal/working-directory fragment remains visible. No readable credential was identified there. Optional presentation/privacy cleanup should be a separately authorized derivative change, preserving originals and updating transformation/hash records. The version/frame evidence and earlier consistency PASS remain valid. |
| **Low** | **PUB-L02** | Existing global Git configuration: `~/.gitconfig`, `user.name` and `user.email` | Author name and email are configured; their values are withheld. Verify that they are the identity/address intended for public commit metadata before the first commit. No repository-specific override exists because this is not yet a Git working tree. No unwanted attribution marker was found. |

PUB-M01 is a privacy decision, not a finding of an exposed password or token. The warnings do not establish compromise or change any investigation confidence/rating.

## Complete repository inventory

### Directory inventory

| Directory | Purpose | Final-repository disposition |
|---|---|---|
| `teamcity-investigation/` | Project root and README | Include as repository root. |
| `evidence/` | Five source evidence/metadata documents | Include; retain provenance and privacy boundaries. |
| `report/` | Integrated/supporting reports and QA records | Include; distinguish historical QA from current sign-off. |
| `report/figures/` | Seven selected PNGs and derivative manifest | Include; retain exact filenames and source traceability. |

Before this audit output, the directory contained **21 regular files**, **3 subordinate directories**, **14 UTF-8 Markdown/CSV text files** and **7 PNGs**. There were no hidden entries, symlinks, special files or empty unexpected directories. Total pre-audit file size was **5,735,871 bytes** (approximately **5.47 MiB**).

### Every pre-existing file

Paths below are relative to the project root. All files have an investigation/reporting purpose; none is a temporary artifact.

| File | Bytes | Purpose and inclusion recommendation |
|---|---|---|
| [README.md](../README.md) | 13,930 | Main GitHub landing page; include. |
| [evidence/ATTACK_TIMELINE.md](../evidence/ATTACK_TIMELINE.md) | 9,894 | Selected chronology and time/association limits; include. |
| [evidence/MITRE_ATTACK_MAPPING.md](../evidence/MITRE_ATTACK_MAPPING.md) | 17,568 | Canonical seven-technique assessment; include. |
| [evidence/PRESERVATION_NOTES.md](../evidence/PRESERVATION_NOTES.md) | 2,421 | Preservation/provenance record; include subject to PUB-M01 privacy decision. |
| [evidence/SCREENSHOT_MANIFEST.csv](../evidence/SCREENSHOT_MANIFEST.csv) | 15,807 | 70-original inventory and hashes; include subject to PUB-M01 privacy decision. |
| [evidence/TECHNICAL_EVIDENCE_REGISTER.md](../evidence/TECHNICAL_EVIDENCE_REGISTER.md) | 14,236 | Canonical observations, packet references and gaps; include. |
| [report/DETECTION_AND_RESPONSE.md](DETECTION_AND_RESPONSE.md) | 61,310 | Corrected proposed detections and response guidance; include. |
| [report/DETECTION_AND_RESPONSE_QA.md](DETECTION_AND_RESPONSE_QA.md) | 39,647 | Historical pre-correction QA; include as audit history. |
| [report/EXECUTIVE_SUMMARY.md](EXECUTIVE_SUMMARY.md) | 7,640 | Management summary; include. |
| [report/FINAL_CONSISTENCY_QA.md](FINAL_CONSISTENCY_QA.md) | 25,838 | Final consistency PASS and correction closure; include. |
| [report/INVESTIGATION_REPORT.md](INVESTIGATION_REPORT.md) | 102,891 | Authoritative integrated report; include subject to PUB-M01 privacy decision. |
| [report/TECHNICAL_FINDINGS.md](TECHNICAL_FINDINGS.md) | 47,342 | Corrected technical analysis and figure captions; include. |
| [report/TECHNICAL_FINDINGS_QA.md](TECHNICAL_FINDINGS_QA.md) | 31,917 | Historical pre-correction technical QA; include as audit history. |
| [report/figures/DERIVATIVE_MANIFEST.csv](figures/DERIVATIVE_MANIFEST.csv) | 2,378 | Source/figure hashes and transformation provenance; include. |
| [report/figures/F-001_EV-008.png](figures/F-001_EV-008.png) | 717,362 | Selected redacted/presentation figure; include, with optional PUB-L01 cleanup. |
| [report/figures/F-002_EV-014.png](figures/F-002_EV-014.png) | 538,819 | Selected redacted/presentation figure; include. |
| [report/figures/F-003_EV-062.png](figures/F-003_EV-062.png) | 711,815 | Selected redacted/presentation figure; include. |
| [report/figures/F-004_EV-065.png](figures/F-004_EV-065.png) | 768,685 | Selected redacted/presentation figure; include. |
| [report/figures/F-005_EV-066.png](figures/F-005_EV-066.png) | 966,060 | Selected redacted/presentation figure; include. |
| [report/figures/F-006_EV-068.png](figures/F-006_EV-068.png) | 761,122 | Selected redacted/presentation figure; include. |
| [report/figures/F-007_EV-070.png](figures/F-007_EV-070.png) | 879,189 | Selected redacted/presentation figure; include. |

### Permitted audit output

| File | Purpose | Disposition |
|---|---|---|
| `report/PUBLICATION_READINESS_AUDIT.md` | This publication-readiness checkpoint | Include with the QA records; contains locations/categories rather than discovered sensitive values. |

After adding only this requested output, the expected inventory is **22 regular files**, **15 text files**, **7 PNGs** and the same **3 subordinate directories**. No source file, figure or directory was changed.

## Sensitive-data scan methodology and results

### Text inspection

All 14 pre-existing Markdown/CSV files were scanned as UTF-8, including reports, historical QA, manifests and README. There were no decoding errors. Searches covered:

- Password/secret assignments and authenticated URL user-info.
- HTTP Bearer/Basic authentication, JWT-shaped strings and common API/cloud/provider token formats.
- Private-key PEM/OpenSSH/PGP markers and connection-string secret fields.
- Email addresses, international phone-number patterns and local account/home-directory paths.
- Attribution markers and co-author trailers.

Redacted placeholders, schema field names, proposed command templates and SHA-256 preservation hashes were distinguished from credential values. Matches were recorded by **file, line, column and category**, without printing values.

| Category | Result in pre-existing project text |
|---|---|
| Password/token/API-key/private-key/authenticated-URL candidates | No detected unredacted values |
| Email addresses and international phone-number patterns | No matches |
| Local account/home-path metadata | **73 occurrences**, limited to PUB-M01 locations |
| Unwanted attribution or co-author trailers | No matches |

This is pattern-based/static inspection, not validation that a candidate credential would work. It is not a guarantee against every encoding or obfuscation. No online credential check or external upload was performed.

### Seven selected figures

All seven PNGs were reviewed at native resolution for readable credentials, authentication fields, packet-byte representations, personal/workstation information and unrelated desktop content. Local OCR tooling was unavailable; no automated OCR accuracy claim is made.

Binary checks confirmed **RGB**, **single-frame PNGs**, **no alpha channel**, **no parsed metadata**, **no PNG text/EXIF chunks**, and **no trailing data after the PNG end**. No layered image source or embedded original was found. These checks do not claim pixel-steganography analysis.

| Selected figure | Sensitive-data/publication result |
|---|---|
| `report/figures/F-001_EV-008.png` | No readable password/token/private key; local terminal fragment noted in PUB-L01. Version, node/application and network metadata remain visible. |
| `report/figures/F-002_EV-014.png` | Authentication/CSRF region remains opaquely masked; no readable secret detected elsewhere. |
| `report/figures/F-003_EV-062.png` | Request/command and packet data; no readable credential detected. |
| `report/figures/F-004_EV-065.png` | File-read request/search term; no returned credential contents or secret value detected. |
| `report/figures/F-005_EV-066.png` | Both decoded credential occurrences and encoded packet-byte pane remain masked; no readable credential value detected. |
| `report/figures/F-006_EV-068.png` | Authentication-header bytes remain masked; preserved Docker command bytes contain no detected credential value. |
| `report/figures/F-007_EV-070.png` | Authentication/CSRF area remains masked; no readable credential value detected. |

Lab IPs, HTTP Host/URI values, software versions, dates and application/node identifiers remain visible because they support the evidence. They are not automatically authentication secrets or established personal identities. Their inclusion remains subject to the intended public evidence scope. No address, identifier, author identity or sensitive matched value is transcribed in this audit.

## Evidence preservation and SHA-256 records

The [screenshot manifest](../evidence/SCREENSHOT_MANIFEST.csv) passes record/accounting checks:

- **70 entries**, IDs exactly EV-001–EV-070, with 70 unique filenames, paths and recorded SHA-256 values.
- All recorded hashes have the expected 64-character lowercase hexadecimal format.
- All 70 referenced originals exist as regular files; recorded sizes and UTC modification timestamps match current metadata.
- All seven selected source IDs/filenames/hashes agree between the original and [derivative manifest](figures/DERIVATIVE_MANIFEST.csv).
- The actual bytes of all seven repository figures match their recorded **derivative** SHA-256 hashes.
- Ten source-document hash records in [FINAL_CONSISTENCY_QA.md](FINAL_CONSISTENCY_QA.md) match the current corresponding files.

**The 70 original screenshots were not reopened or freshly content-hashed in this audit.** Existing full-collection hashing results remain historical preservation/QA records; metadata/record consistency is not a new whole-collection content-integrity certification. No source packets or original screenshot contents were re-examined.

The originals are external to this directory; the seven figures are clearly labelled presentation derivatives in README, reports and their separate manifest. Public derivative hashes must not be substituted for original preservation hashes. Neither set establishes original authenticity, successful execution or a formal chain of custody.

## Documentation and investigation-boundary checks

Across the pre-existing Markdown files, **123 internal relative document/image links resolve**, including all README/report image references. No invalid evidence ID was found. The seven unique figure files are the expected EV-008/EV-014/EV-062/EV-065/EV-066/EV-068/EV-070 selections.

[README.md](../README.md) and the [integrated report](INVESTIGATION_REPORT.md) retain the canonical seven ATT&CK techniques: T1190, T1505.003, T1083, T1059.004, T1565.001, T1610 and T1611. Names, tentative/attempt status and confidence follow the existing mapping. References to excluded techniques in historical/source documents explain exclusion rather than adding assignments.

Publication-facing limitations remain explicit:

- Incident severity is undetermined; High/Medium values are provisional response priorities.
- Command submission and HTTP 200 do not establish command success or recovered credentials.
- Privileged-only Docker and host-root-bind/chroot requests remain distinct.
- Docker requests/configuration do not independently prove startup, escape or host compromise.
- Timestamp mode/reference, address relationships, authorization and attribution remain unresolved.
- Account/token creation monitoring remains preventive, not an established finding.
- Six KQL examples remain proposed and untested; response guidance does not claim actions performed in the lab.

The final consistency QA closes the five earlier required corrections. The two earlier QA reviews retain historical verdicts/line references; README and the integrated report explain their role. External web references were not checked online, and GitHub rendering was not tested by publication.

## Git configuration and attribution

No `.git` file/directory or containing Git working tree was found. There is no repository index, commit history, local configuration or remote to audit. No Git repository was initialized.

Read-only effective configuration inspection found an existing global `~/.gitconfig` with author name/email configured. Identity values were captured only for presence checks and were not printed. No configured commit template, custom hook path, sensitive configuration key or unwanted attribution/co-author marker was found in that configuration. No actual co-author trailer or unwanted attribution was found in the pre-existing project text or selected figure review.

No Git configuration was changed. PUB-L02 concerns choosing the intended future public author identity, not an existing project-file secret.

## Inclusion, exclusion and publication hygiene

### Recommended inclusion

Include the documentation, five evidence records, derivative manifest, seven selected figures and this audit listed in the inventory. Retain historical QA with the final closure record. PUB-M01 requires a privacy decision before releasing the affected records unchanged; source preservation must remain intact if a separate public sanitization is later authorized.

### Recommended exclusion

The following are **not currently present in the project directory** and should not be added indiscriminately:

- External raw originals, particularly source views known from existing records to contain credential/authentication or lab-answer material. This audit covers the selected redacted derivatives, not raw-original public suitability.
- Raw captures, unredacted command/HTTP exports, recovered secret files or credentials.
- Global/local machine configuration, environment files, private keys, authentication stores and credential-bearing Git configuration.
- Temporary copies, generated previews, caches, virtual environments, editor state, OS junk and unrelated screenshots.

No current file is classified as an unexpected/temp artifact requiring deletion. Do not automatically exclude `evidence/`, the manifest or PNGs: they are intentional, linked deliverables, and exclusion would damage traceability or navigation.

### .gitignore recommendation

**No .gitignore is necessary for the current snapshot:** every existing project file is intentional, and no cache, environment, local configuration or temporary output was found. No ignore file or rules were created. If later work introduces excluded artifacts, review those actual paths and authorize appropriate rules before staging; do not use an ignore file as a substitute for reviewing sensitive files.

## Final checklist before GitHub publication

### Completed by this audit

- [x] Complete directory/file inventory recorded; no unexpected artifacts or symlinks.
- [x] All pre-existing text files and seven selected figures checked for sensitive data.
- [x] Manifest accounting, existing SHA-256 relationships and seven actual derivative hashes verified.
- [x] Existing internal links/images, evidence IDs, canonical ATT&CK set and report limitations checked.
- [x] Existing Git configuration inspected without initialization; unwanted attribution/trailers absent.
- [x] All 21 pre-existing project-file SHA-256 hashes remain unchanged; only this audit added.
- [x] No original screenshot audit, PCAP investigation, report rewrite, Git initialization/staging/commit/push or external upload performed.

### Decisions and checks before an authorized release

- [ ] Resolve PUB-M01: accept the local-path disclosure or authorize a public sanitization plan that preserves restricted originals/hash records and working public links.
- [ ] Decide whether to remove the optional PUB-L01 terminal fragment through an authorized presentation-only revision with updated derivative provenance.
- [ ] Confirm the intended public Git author name/email and absence of unwanted trailers before the first commit.
- [ ] Review the exact future staging set against this inventory; keep raw originals and local secret/configuration material outside it.
- [ ] Verify GitHub rendering/relative asset packaging in the intended release workflow; no publication was performed to test it here.
- [ ] Scan any subsequently added or changed material before release; this audit covers the current snapshot only.

**Final disposition: READY WITH WARNINGS.** No detected credential/private-key exposure blocks the current document/figure set. Public release should account for the identified local metadata and author-identity choices. Investigation outcomes and incident severity remain undetermined.

