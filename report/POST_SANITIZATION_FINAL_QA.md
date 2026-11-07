# Post-Sanitization Final Publication QA

Verification date: **2026-11-07**. Overall result: **READY**.

The current documentation and seven selected figures are suitable for public GitHub publication as a screenshot-supported investigation of disclosure and attempted activity. All thirteen requested checks pass. The previous local-metadata, F-001 presentation and author-identity warnings are resolved for this snapshot. Incident severity remains **undetermined**.

## Scope and method

This verification used the current versions of the seven requested documents/manifests, all seven selected PNGs, and the supporting findings, detection source, evidence register, timeline and ATT&CK mapping. All 15 existing Markdown/CSV files were scanned; all 22 existing project files were inventoried and hashed. The selected figures were visually inspected at native resolution, independently hashed, checked for embedded metadata, and compared in memory against their original crops outside declared masks.

All 70 external originals were freshly hashed in place using read-only `O_NOATIME` reads. No raw original was visually re-audited for publication suitability, and no PCAP investigation, KQL execution or online credential validation was performed.

## Requested verification results

| Item | Result | Verification |
|---|---|---|
| **1. Three local-metadata warnings** | **PASS — resolved** | The three text-file locations grouped under PUB-M01 in the previous audit are sanitized: `SCREENSHOT_MANIFEST.csv` uses `original_collection_relative_path` rather than `original_absolute_path`; `PRESERVATION_NOTES.md` omits the collection's absolute path and uses repository-relative `evidence/`; the integrated report's Section 4.2 omits the original collection's absolute path. No local account/home-directory path was detected in any existing project text. |
| **2. F-001 terminal cleanup and evidence** | **PASS** | The lower-right terminal/working-directory fragment is completely covered by an opaque, uniform mask at derivative rectangle **[1200, 728, 1512, 759]**. TeamCity **2023.11.3 / build 147512**, HTTP 200 XML, unusual GET routing, selected frame **24711**, displayed Time **1054.290142** and stream **364** remain readable. Every pixel outside the declared mask matches the original crop. |
| **3. Updated F-001 hash** | **PASS** | Actual SHA-256 is **`103047ae11955c61bb74c56d01f1b80691300c5c607ab0e40600fbb307ea2420`**, matching the current derivative manifest. Its transformation record explicitly supersedes the earlier derivative hash and retains the unchanged EV-008 original hash. |
| **4. All 70 original screenshots** | **PASS — 70/70** | IDs are exactly EV-001–EV-070; filenames, collection-relative paths and hashes are unique. Exactly 70 regular files occupy the documented inclusive filename selection, with no missing or additional selection entry. Fresh SHA-256, byte-size and nanosecond UTC modification-time checks match every preservation record. Original file identity, mode, size, access/modification/change times remained unchanged across each hashing read. Historical-manifest equivalence is verified below. |
| **5. Seven derivative hashes** | **PASS — 7/7** | Every selected figure matches its current derivative SHA-256 record. All seven source IDs, filenames and original hashes agree between manifests. Declared dimensions and all pixels outside declared redaction boxes match the originals. |
| **6. Relative links and images** | **PASS** | Markdown parsing found **150 relative links**, all resolving to existing files. **141** occur in README/report documents; the remaining nine are in evidence documents. All **21 image references** resolve to the same seven intended PNGs: seven each in README, the integrated report and technical findings. No relative anchor or HTML-link exception was found. External websites and live GitHub rendering were not tested. |
| **7. Findings, ATT&CK, timeline and evidence** | **PASS** | All seven findings retain their primary/supporting evidence roles, selected frames, exact displayed Time values, command distinctions and confidence boundaries. The seven canonical techniques, statuses and confidences agree with the existing mapping and final consistency QA. No invalid evidence ID or unregistered original filename reference was found. Details appear below. |
| **8. Unsupported success claims** | **PASS** | README and the complete integrated report consistently leave exploitation, plugin acceptance/activation, command execution, credential recovery, file changes, Docker startup, mount/chroot success, escape and host compromise unverified. HTTP 200 and advertised response length are not treated as success. High/Medium values remain provisional response priorities, separate from undetermined incident severity. |
| **9. Six KQL examples** | **PASS** | Exactly six KQL blocks occur in the integrated report. Each carries **PROPOSED AND UNTESTED**, and all six match the corrected detection source verbatim. Schema, parser, lineage, approval and Docker lifecycle/configuration prerequisites remain explicit. No query was compiled, run, deployed or described as tested during this verification. Historical QA query excerpts are not additional final-report examples. |
| **10. README accuracy** | **PASS** | README accurately describes the integrated report, seven findings, eleven detection opportunities, six untested queries, seven-stage proposed response playbook, five evidence documents and seven cropped/redacted derivatives. The 70 originals are inventoried and preserved externally; README does not promise 70 bundled public PNGs. Navigation and figure captions agree with the actual layout. |
| **11. Secrets and unnecessary personal metadata** | **PASS — none detected** | Static scanning of all existing project text and native-resolution inspection of every selected figure found no exposed credential value, API key, usable authentication token or private key. Authentication/CSRF regions, decoded credential fields and encoded credential/header bytes remain masked where required. No unnecessary personal/local account metadata was detected. Relevant lab network, HTTP, software, date and node identifiers remain evidentiary context. The author identity below is intentionally recorded to satisfy item 12. |
| **12. Git author configuration** | **PASS** | Read-only effective configuration checks return exactly **CosmasSaidi <cosmassaidi2@gmail.com>**. No containing Git working tree or project `.git` exists. Configuration was not changed; its file digest and effective identity remained stable during the final checks. |
| **13. Publication hygiene** | **PASS** | Before this output: **22 regular files**, **15 Markdown/CSV files**, **7 PNGs**, and only `evidence/`, `report/`, `report/figures/` below the root. These match the previous audit's expected assembled inventory. No hidden entries, symlinks, special files, caches, environment files, private-key stores, executables, temporary previews or unrelated artifacts were found. After this output: **23 regular files**, with only this requested QA added. |

## Preservation and historical-record reconciliation

The 70 original records cover **Screenshot From 2026-11-03 00-54-22.png** through **Screenshot From 2026-11-04 21-24-13.png**, inclusive. Their hashes identify original screenshot bytes; derivative hashes identify different presentation files.

To verify that sanitization preserved the original records, the pre-cleanup CSV was reconstructed **only in memory** by restoring the historical absolute-path column from the locally resolved original collection. The reconstructed **15,807-byte** CSV exactly matches the pre-cleanup manifest SHA-256 recorded in `FINAL_CONSISTENCY_QA.md`:

`a59500cced4eaf6e9875e34fd2b958778549ca6e1117e71b4560ea3618f10721`

This establishes that all 70 IDs, filenames, original hashes, sizes and timestamps retain the historical preservation values. No reconstructed private-path record was saved or included here.

Eight of the ten source-document hash records in the historical final consistency QA still match current files. The screenshot manifest and preservation notes differ because of the documented publication metadata cleanup. The revised F-001 hash is recorded in the current derivative manifest. These documented snapshot differences do not invalidate original integrity or reopen the earlier five required finding/detection corrections. The previous publication audit remains a historical warning record; this verification records closure without rewriting it.

## Selected figures and current SHA-256 values

Every row passed visual, source-record, derivative-hash and declared-transformation checks.

| Figure / original ID | Current derivative SHA-256 | Visible evidence preserved |
|---|---|---|
| F-001 / EV-008 | `103047ae11955c61bb74c56d01f1b80691300c5c607ab0e40600fbb307ea2420` | TeamCity version/build, response and frame/stream references; terminal fragment masked. |
| F-002 / EV-014 | `ee6286848b3eb0037b76ea1abd8b7adcf663581cba6930728057cbde64e9ca9a` | Upload/archive/JSP command-parameter content, frame 24825/stream 364; authentication/CSRF masked. |
| F-003 / EV-062 | `817d8bae3f671ce6e641e9d0d105056267895add995225aa1509f1035af87de4` | Frame 25572, decoded/encoded ls submission and reassembly; no returned listing. |
| F-004 / EV-065 | `311e2acd20ec9dfdeefb1cbadace6dee4a0be2cce8bfd19b069e44383f0708ed` | Frame 26895, file-read command and reassembly; search input remains distinguishable from output. |
| F-005 / EV-066 | `59d04fb2e56ca19643886bb8366c130c2a87680f59e50ce451b845975b0cfc6a` | Frame 31123, bash/redirection/target and reassembly; both decoded credential occurrences and encoded pane masked. |
| F-006 / EV-068 | `34ece715d3f240a81b17e3f62719639214b2d56d56ff48520cb09617ef6f835c` | Frame 32002, privileged-only Docker request and 43-byte body; authentication-header bytes masked. |
| F-007 / EV-070 | `82132cc18309f37355ca27da1092c7b0541eef6125f03108188d0e6405fb2853` | Root-bind/chroot body, stream 601, footer 32111 versus selection 32010 and response headers; authentication/CSRF masked. |

F-001/F-002 are **1512×759**; the other five are **1920×802**. All are single-frame RGB PNGs without alpha, parsed metadata, text/EXIF chunks or trailing payload. Their only PNG chunk types are IHDR, IDAT and IEND; all checked chunk CRCs are valid. Masks are flattened into pixels.

## Finding, timeline and mapping consistency

| Finding | Primary / supporting evidence | Selected frame / displayed Wireshark Time | Consistent assessment |
|---|---|---|---|
| F-001 | EV-008; EV-014 later context | 24711 / 1054.290142; stream 364 | Version disclosure; exploitation hypothesis remains Low confidence. |
| F-002 | EV-014; EV-062 later path context | 24825 / 1071.315015; stream 364 | Upload submission; placement interpretation remains tentative Moderate. |
| F-003 | EV-062; EV-060/EV-061 repeated views; EV-014 component context | 25572 / 1122.563990; stream unestablished | ls submission; discovery High, webshell interpretation Moderate. |
| F-004 | EV-065 | 26895 / 1524.276831; stream unestablished | File-read submission; no returned credentials and no technique assigned. |
| F-005 | EV-066 | 31123 / 1721.175300; stream unestablished | Explicit bash/write submission; interpreter High, intended manipulation Moderate. |
| F-006 | EV-068; EV-069 repeated command; EV-070 stream association | 32002 / 2039.893932; stream 601 association Moderate | Privileged-only deployment request; High command fit, startup unverified. |
| F-007 | EV-070 | Footer 32111 / 2065.593291; stream 601 | Root-bind/chroot request; Moderate frame association and overall mapping. |

The four recorded reassemblies agree: **25566 (527) + 25572 (6) = 533**, **26889 (528) + 26895 (26) = 554**, **31117 (528) + 31123 (99) = 627**, and **31996 (528) + 32002 (43) = 571 bytes**. F-007's body is **62 bytes**; no reassembly-segment list is invented.

The seven mappings remain:

| Technique | Finding(s) | Status / confidence |
|---|---|---|
| T1190 — Exploit Public-Facing Application | F-001 | Tentative / Low. |
| T1505.003 — Server Software Component: Web Shell | F-002/F-003 | Tentative / Moderate. |
| T1083 — File and Directory Discovery | F-003 | Observed attempt / High. |
| T1059.004 — Command and Scripting Interpreter: Unix Shell | F-005 | Observed attempt / High. |
| T1565.001 — Data Manipulation: Stored Data Manipulation | F-005 | Tentative / Moderate; achieved Impact unverified. |
| T1610 — Deploy Container | F-006/F-007 | Observed attempts; F-006 High command fit/Moderate stream association, F-007 Moderate overall. |
| T1611 — Escape to Host | F-007 only | Tentative / Moderate. |

The read precedes the write and cannot verify it. EV-069 adds no event. Frames 31124/32003 remain client POSTs; nearby HTTP 200 rows 32008/32010 remain unpaired result evidence. F-007's footer packet 32111 is distinct from selection 32010. Its four advertised response bytes provide no readable command output. F-006 has no root bind/chroot; F-007 has no privileged flag. Absolute event times, capture reference mode, daemon location and initial containment remain unresolved.

Historical source labels noted in the final consistency QA do not establish actor identity or successful effects. Preventive identity-change monitoring remains a recommendation, without a new case finding or ATT&CK assignment.

## Automated secret-scanning limitations

Scanning covered credential/secret assignments, authenticated URLs, private-key markers, common provider-token formats, JWTs, Basic/Bearer values, email/phone patterns and local account paths. Six redacted secret placeholders were correctly distinguished from values. One Basic/Bearer-pattern candidate in the previous audit's scan-method description was reviewed and is descriptive prose, not authentication material.

These are local pattern checks supplemented by visual review, not a guarantee that every secret encoding or format is detectable. Unknown token formats, split/obfuscated values, arbitrary base64/encrypted content and pixel steganography can evade them. No dedicated secret-scanner executable or OCR engine was available; no OCR coverage or online validity test is claimed. Native-resolution inspection and flattened PNG/metadata checks reduce ordinary redaction risks without certifying absence of hidden information.

Raw originals were integrity-checked, not approved for public release. Known unredacted source views remain outside the public project. Hashes do not establish authenticity, formal chain of custody, exploitation or execution. External-link availability, a particular GitHub viewport and later additions are outside this snapshot verification.

These residual method limits are not detected publication defects and do not change the **READY** result.

## Reviewed versions

Paths are relative to the project root; these hashes identify the latest requested inputs used in this verification.

| Input | SHA-256 |
|---|---|
| `README.md` | `3a30d54fb8c3f96c7fb6edcfabbfac95c1c9e9195f94757a67dcf9b2855cf61b` |
| `report/INVESTIGATION_REPORT.md` | `8fec14013772dec8e75a6df4d7e9dd34650d0fb9fbd86b4559015a4d66d2de39` |
| `report/PUBLICATION_READINESS_AUDIT.md` | `aaf9d613c04d37d4048561d517d83a441de0271dc4b6147a411b27b67826506d` |
| `report/FINAL_CONSISTENCY_QA.md` | `56e0bf5ee262b6291775de3ab45dd3b0f9e91105b3c763f894101132cc500e5d` |
| `evidence/SCREENSHOT_MANIFEST.csv` | `b4ee8496e3c5a292336759a91b6bf55b254406eb8a99d090cadbab30bcd4943b` |
| `evidence/PRESERVATION_NOTES.md` | `4bf9341e4a10eff20276a276d0d15f3bf9c13f5d471128061ccbecdae168c0fc` |
| `report/figures/DERIVATIVE_MANIFEST.csv` | `c26a0c614a8da7a77cc4b017c3c22fbb8b21bab31ba4d071ecb48d4097c8e34a` |

## Read-only confirmation and publication recommendation

**The verification was read-only for all existing project files, original screenshots and Git configuration.** Before/after SHA-256 comparison confirmed all **22 pre-existing project files** unchanged. The only created file is **`report/POST_SANITIZATION_FINAL_QA.md`**. No existing file was edited, renamed, moved or deleted; no temporary file, cache, reconstructed private manifest or additional figure was created.

Git was not initialized. Nothing was staged, committed, pushed, published or uploaded, and Git configuration was not changed.

**Final recommendation: suitable for public GitHub publication of the current documentation and seven sanitized derivatives, preserving the present relative directory structure.** No further source correction is required by this verification. Keep external originals and local configuration outside that publication set; inspect any later additions or changes before release.

