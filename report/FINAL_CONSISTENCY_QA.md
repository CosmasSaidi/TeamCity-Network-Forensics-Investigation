# JetBrains TeamCity — Final Consistency and Evidence-Integrity QA

Review date: **2026-11-07**. Overall assessment: **PASS**.

## Overall assessment and scope

The current investigation documents can be integrated into a final **screenshot-supported assessment of disclosure and attempted activity**. The seven findings, evidence IDs, selected frames, recorded Wireshark Time values, response priorities and ATT&CK assessments agree. The seven report figures are correctly sourced and their captions describe visible request/response material without asserting successful incident outcomes. **Incident severity remains undetermined.** High response priority reflects potentially serious requested capabilities, not confirmed successful actions or a High incident-severity rating.

No Critical, High or Medium consistency defect or evidence-integrity discrepancy was identified. The two earlier QA reviews are historical records of reports before their required corrections. All five required corrections are verified as closed below; their original verdicts and line references must be read in that historical context. No existing source document needs editing to complete this review. This file records the current integration decision without altering the earlier audit trail.

### Documents reviewed

- [EXECUTIVE_SUMMARY.md](EXECUTIVE_SUMMARY.md).
- [TECHNICAL_FINDINGS.md](TECHNICAL_FINDINGS.md).
- [TECHNICAL_FINDINGS_QA.md](TECHNICAL_FINDINGS_QA.md).
- [DETECTION_AND_RESPONSE.md](DETECTION_AND_RESPONSE.md).
- [DETECTION_AND_RESPONSE_QA.md](DETECTION_AND_RESPONSE_QA.md).
- [TECHNICAL_EVIDENCE_REGISTER.md](../evidence/TECHNICAL_EVIDENCE_REGISTER.md).
- [ATTACK_TIMELINE.md](../evidence/ATTACK_TIMELINE.md).
- [MITRE_ATTACK_MAPPING.md](../evidence/MITRE_ATTACK_MAPPING.md).
- [SCREENSHOT_MANIFEST.csv](../evidence/SCREENSHOT_MANIFEST.csv).
- [PRESERVATION_NOTES.md](../evidence/PRESERVATION_NOTES.md).

The [derivative manifest](figures/DERIVATIVE_MANIFEST.csv) and all seven selected report figures were also checked. Source line references below refer to the versions recorded in this review. **TF** means `report/TECHNICAL_FINDINGS.md`; **ER** means `evidence/TECHNICAL_EVIDENCE_REGISTER.md`; **TL** means `evidence/ATTACK_TIMELINE.md`; **D&R** means `report/DETECTION_AND_RESPONSE.md`.

### Method and limits

This review compared the documents and existing evidence records, inspected the seven presentation figures for caption accuracy, checked internal links and reconciled manifest entries. For the seven selected figures only, original files were read using `O_NOATIME` for SHA-256 and in-memory crop/redaction verification. Original names/hashes were compared across both manifests; derivative hashes and every pixel outside declared masks were checked. No temporary files or new figures were created.

**The PCAP investigation and the original screenshot-content audit were not rerun.** No original screenshot was visually re-audited, and the remaining 63 originals were not freshly content-hashed or examined for incident behaviour. The 70-file accounting check verified manifest completeness, current paths, sizes and modification timestamps. Previous full-collection hash checks remain documented historical checks, not new results of this review. No KQL, detection rule or response action was executed; no fresh external-source verification is claimed.

Agreement among documents that inherit the same screenshots is not independent corroboration of execution. Preservation/reference integrity does not establish original authenticity, a formal chain of custody or successful compromise.

## Prioritized issue list

| Priority | ID | Exact references | Assessment and disposition |
|---|---|---|---|
| Critical | — | All reviewed sources | None identified. |
| High | — | All reviewed sources | None identified. |
| Medium | — | Current TF and D&R | None outstanding. Earlier required corrections are closed in the next section. |
| Low | FC-001 | **“Publication blockers and final disposition”**, `report/TECHNICAL_FINDINGS_QA.md:213–219`; **“Final disposition”**, `report/DETECTION_AND_RESPONSE_QA.md:348–350`; snapshot identification at `report/DETECTION_AND_RESPONSE_QA.md:3,13` | Historical QA verdicts and old source-line references can be mistaken for current blockers when assembled without context. **Resolved for integration by this review's closure register and version record.** Retain the QA files unchanged as history; use this final assessment for current sign-off. TF already records its correction closure at TF:460. |
| Low | FC-002 | **“Credential-file write request”**, ER:59; **“Mapping table”**, `evidence/MITRE_ATTACK_MAPPING.md:35`; authorization caveats at TF:155,450 and `report/EXECUTIVE_SUMMARY.md:55` | “Attacker-supplied” and the mapping row label “Malicious plugin upload request” are stronger wording than the established authorization/actor evidence. They occur within interpretations and qualified mapping context, not a proven actor attribution. **Optional assembly improvement:** prefer “submitted/requester-supplied” and “suspicious upload”; do not turn those inherited labels into an assertion of actor identity or unauthorized activity. No source edit is required by this review. |
| Low | FC-003 | **“Embedded screenshot and caption review”**, `report/TECHNICAL_FINDINGS_QA.md:185`; figure captions at TF:73,125,175,226,278,337,393 | Native figures are readable, but a narrow export may reduce packet/code legibility. **Optional presentation check:** preserve full-resolution access and verify command/frame text in the eventual rendering. Current Markdown has no figure replacement blocker. |
| Low | FC-004 | **“Optional improvements”**, `report/DETECTION_AND_RESPONSE_QA.md:340–346`; current hunt windows at D&R:179,200,230,264,284,327; collection guidance at D&R:338–354; scheduling at D&R:366 | Earlier optional improvements remain applicable: scheduling/deduplication, modern audit-rule alternatives, ancestry and workload enrichment, and control ownership. They are implementation/presentation work, not missing case evidence or unresolved required report corrections. Operational adoption still requires the prerequisites at D&R:460. |

There are **no required source corrections before integration**. Open evidence gaps and detection deployment prerequisites are distinguished from report defects below.

## Closure of earlier required QA corrections

| Earlier correction | Original QA reference | Current implementation and closure evidence | Result |
|---|---|---|---|
| R-001 — Separate response priority from incident severity | `report/TECHNICAL_FINDINGS_QA.md:191–199` | TF **“Response priority, potential impact and evidence confidence”**, lines 23–53, separates all four fields; each of the seven findings records undetermined incident severity. High priorities remain F-002/F-006/F-007. TF:460 explicitly records closure. | **Closed** |
| R-002 — Qualify F-001 | `report/TECHNICAL_FINDINGS_QA.md:201–209` | TF:55 reads **“TeamCity Server Identification and Potential Vulnerability Exposure”**. TF:61–83 preserves version 2023.11.3, build 147512 and the Low-confidence CVE-2024-27198 hypothesis without claiming exploitation. | **Closed** |
| QA-001 — Boolean grouping | `report/DETECTION_AND_RESPONSE_QA.md:27–49` | D&R **“D-004 — Shell processes associated with TeamCity”**, line 73, requires a shell-start event and approval condition for both identity branches. **“D-010 — Suspicious administrative account, role or token creation”**, line 133, requires an identity-change event for both approval/context branches. D&R:131 retains preventive scope; D&R:336 discloses Q-006's narrower approval branch. | **Closed** |
| QA-002 — Command-text indicators | `report/DETECTION_AND_RESPONSE_QA.md:51–81` | D&R **“Q-002 — Docker/chroot process leads”**, lines 192–218, uses `PrivilegedFlagTextPresent`, `RootBindFlagTextPresent` and `ChrootProcessNameMatch`. Missing command text produces null indicators. Prose distinguishes text matching, parsed requests, daemon lifecycle, inspected settings and host access. | **Closed** |
| QA-003 — Root-bind configuration and unknown data | `report/DETECTION_AND_RESPONSE_QA.md:83–118` | D&R **“Q-005 — Inspected Docker configuration and root-bind status”**, lines 279–320, preserves Confirmed/Not observed/Unknown configuration states, guards null/non-array mount data and retains all states in the output. Lifecycle observations are separate. D&R:257 defines complete inspection and missing-data semantics. | **Closed** |

Q-005's **Confirmed** label concerns inspected root-bind configuration in a proposed telemetry design. It is neither a new finding about this case nor proof of a mounted filesystem, container startup with that configuration, `chroot` or host access. Individual mount-object validity and completeness still depend on the declared ingestion contract. Missing lifecycle rows require collector-health checks and inventory reconciliation; a zero-result query cannot establish safety.

## Finding-to-evidence and timeline consistency

All seven rows below pass. Numeric Time values are transcriptions, with the relative-seconds interpretation provisional; they are not absolute event times. The selected order is **24711 → 24825 → 25572 → 26895 → 31123 → 32002 → 32111**.

| Finding | Primary/supporting evidence and role | Selected frame / Wireshark Time | Exact cross-references |
|---|---|---|---|
| F-001 | EV-008 primary; EV-014 later upload context only | 24711 / 1054.290142; stream 364 | TF:65–77; ER:15–20; TL:17,27; D&R:15 |
| F-002 | EV-014 primary; EV-062 subsequent matching-path context | 24825 / 1071.315015; stream 364 | TF:117–133; ER:24–29; TL:18,28; D&R:16 |
| F-003 | EV-062 primary; EV-060/EV-061 repeated supporting views; EV-014 component context | 25572 / 1122.563990; stream unestablished | TF:167–179; ER:33–38; TL:19; D&R:17 |
| F-004 | EV-065 primary | 26895 / 1524.276831; stream unestablished | TF:218–236; ER:42–47; TL:20; D&R:18 |
| F-005 | EV-066 primary; earlier read supplies chronology, not write verification | 31123 / 1721.175300; stream unestablished | TF:270–294; ER:51–61; TL:21; D&R:19 |
| F-006 | EV-068 primary; EV-069 repeats its command; EV-070 supplies stream association only | 32002 / 2039.893932; stream 601 association Moderate | TF:329–351; ER:65–79; TL:22; D&R:20 |
| F-007 | EV-070 primary; EV-068 is the separate earlier Docker command | Footer packet 32111 / 2065.593291; stream 601; body/frame association Moderate | TF:385–415; ER:83–99; TL:23; D&R:21 |

Registered reassembly values also agree: F-003 **25566 (527) + 25572 (6) = 533 bytes**; F-004 **26889 (528) + 26895 (26) = 554**; F-005 **31117 (528) + 31123 (99) = 627**; F-006 **31996 (528) + 32002 (43) = 571**. F-007 has a **62-byte** displayed body and no assigned reassembly-segment list. No stream number is invented for 25572, 26895 or 31123.

Frames **31124/32003** remain client POSTs, not confirming responses. HTTP 200 rows **32008/32010** are not command-success evidence. F-007 uses footer **32111**, not background selection **32010**; following headers advertise four bytes but show no readable command output or response-frame identifier. See ER:103–110, TL:39–40 and TF:456.

The GET routing line in EV-008 is an explicitly disclosed visibility clarification at TF:77,454 and `report/TECHNICAL_FINDINGS_QA.md:61,163`. The older ER:19/TL:37 gaps about the exact triggering request are not silently resolved: independent request-frame linkage, precise pairing, authorization and exploit effects remain unverified. This is a difference in documented inspection scope, not contradictory exploit evidence.

## Figure-to-evidence verification

For **every row**, the original source SHA-256 matched both manifests; the derivative SHA-256 matched `DERIVATIVE_MANIFEST.csv`; dimensions matched the declared crop; and pixels outside declared redaction boxes matched the specified source. Report figures are derivatives of existing evidence, not additional independent events. “Manifest line” refers to `evidence/SCREENSHOT_MANIFEST.csv`; “derivative line” to `report/figures/DERIVATIVE_MANIFEST.csv`.

| Figure / evidence ID | Exact original screenshot | Manifest / derivative lines | Visible support and caption reference | Result |
|---|---|---|---|---|
| [F-001_EV-008.png](figures/F-001_EV-008.png) / EV-008 | `Screenshot From 2026-11-03 01-41-04.png` | 9 / 2 | Version 2023.11.3/build 147512, HTTP 200, selected frame 24711 and footer stream 364. TF:71–73 describes identification, not exploitation. | **PASS** |
| [F-002_EV-014.png](figures/F-002_EV-014.png) / EV-014 | `Screenshot From 2026-11-03 02-10-16.png` | 15 / 3 | Clipped upload path, archive/JSP content, `request.getParameter("cmd")`, frame 24825/stream 364. TF:123–129 distinguishes submission from installation/activation and attributes POST to the register. | **PASS** |
| [F-003_EV-062.png](figures/F-003_EV-062.png) / EV-062 | `Screenshot From 2026-11-04 20-53-31.png` | 63 / 4 | Selected POST/frame 25572, form value `ls`, packet bytes and reassembly. TF:173–175 claims no returned directory listing. | **PASS** |
| [F-004_EV-065.png](figures/F-004_EV-065.png) / EV-065 | `Screenshot From 2026-11-04 20-58-29.png` | 66 / 5 | Frame 26895, encoded/decoded `cat /tmp/Creds.txt`, reassembly and analyst search field. TF:224–226 correctly excludes search text as file-content evidence. | **PASS** |
| [F-005_EV-066.png](figures/F-005_EV-066.png) / EV-066 | `Screenshot From 2026-11-04 20-59-56.png` | 67 / 6 | Frame 31123, visible `bash -c`/redirection structure, target path and reassembly. TF:276–288 describes submission; both decoded credential occurrences and encoded pane remain masked. | **PASS** |
| [F-006_EV-068.png](figures/F-006_EV-068.png) / EV-068 | `Screenshot From 2026-11-04 21-18-40.png` | 69 / 7 | Frame 32002, privileged-only command, 43-byte body, reassembly and nearby HTTP status rows. TF:335–337 does not infer startup and attributes stream membership separately to EV-070. | **PASS** |
| [F-007_EV-070.png](figures/F-007_EV-070.png) / EV-070 | `Screenshot From 2026-11-04 21-24-13.png` | 71 / 8 | Root-bind/chroot body, stream 601, footer 32111, background selection 32010 and four-byte response headers. TF:391–409 correctly states that no readable output is displayed. | **PASS** |

F-001/F-002 are **1512×759**; the other five are **1920×802**. All are RGB. The masks in F-002/F-005/F-006/F-007 remain visible editorial changes and preserve the relevant request evidence. Visual checks of the seven report figures and text screening of the reviewed Markdown found no unredacted credential assignments or usable Bearer-token values. This is not a certification that raw original screenshots are suitable for inclusion as report figures.

## ATT&CK, severity, scope and response consistency

The canonical assignments are the seven techniques in `evidence/MITRE_ATTACK_MAPPING.md:34–42,66–69`. They agree with TF's individual mapping sections, `report/EXECUTIVE_SUMMARY.md:41–49`, `report/TECHNICAL_FINDINGS_QA.md:147–155`, D&R:15–23 and `report/DETECTION_AND_RESPONSE_QA.md:154–162`.

| Technique | Finding(s) | Consistent assessment and confidence |
|---|---|---|
| T1190 — Exploit Public-Facing Application | F-001 | Tentative, **Low**; CVE-2024-27198 remains a hypothesis. |
| T1505.003 — Server Software Component: Web Shell | F-002/F-003 | Tentative, **Moderate**; upload/use interpretation, not installation or persistence. |
| T1083 — File and Directory Discovery | F-003 | Observed attempt, **High**; submitted `ls`, not a returned listing. |
| T1059.004 — Command and Scripting Interpreter: Unix Shell | F-005 | Observed attempt, **High**; explicit `bash -c`, not inferred from other commands. |
| T1565.001 — Data Manipulation: Stored Data Manipulation | F-005 | Tentative, **Moderate**; intended stored-data manipulation under Impact, not a proven write or achieved impact objective. |
| T1610 — Deploy Container | F-006/F-007 | Observed attempts; F-006 **High command-fit / Moderate stream association**; F-007 **Moderate overall**. Neither establishes startup. |
| T1611 — Escape to Host | F-007 only | Tentative, **Moderate**; depends on initial containment/daemon context. Not assigned to F-006's privileged flag alone. |

F-004 has no technique assigned. References to excluded T1592.002/T1552.001/T1105 explain their exclusion and do not create additional assignments. Seven techniques describe aspects of seven selected packet events, not seven successful techniques or seven separate compromises.

**Two Docker requests remain explicit:** F-006 requests `docker run --rm -it --privileged ubuntu` with no root bind/chroot; F-007 requests `docker run --rm -it -v /:/host ubuntu chroot /host` with no privileged flag. Docker daemon identity and initial namespaces/privileges remain unknown. A host-root bind request is distinct from a successful mount; `chroot` alone does not establish all-namespace escape.

**No unsupported success conclusion was found.** Exploitation, upload acceptance/activation, command execution, directory output, credential recovery/theft, file modification, Docker creation/startup, mount/chroot success, container escape and host compromise remain unverified. A high-confidence command transcription does not establish its execution. Version disclosure does not establish effective patch state or a confirmed exploitable configuration.

**Executive framing passes:** `report/EXECUTIVE_SUMMARY.md:13,21–33,53–57,61–74` limits scope to screenshots/selected events, describes conditional security implications, leaves authorization/actor identity and business impact unresolved, and separates High response priority from incident severity. TF:30–32,45–51 and D&R:7,15–21 retain the same priorities and undetermined severity.

**Identity monitoring remains preventive:** ER contains no finding establishing administrative account/token creation. D&R:23,129–137,322–336 explicitly labels that monitoring preventive and retains failed/unknown outcomes. A visible administrative request path or inventory-monitoring recommendation does not prove account/token creation or supply an additional case technique.

**Response recommendations remain proposals:** D&R:5,37,374–430,460–464 labels detection logic and the seven-stage playbook as untested/not performed. TF:53 and `report/EXECUTIVE_SUMMARY.md:68` likewise distinguish recommendations from actions taken. No existing enterprise telemetry, alert, containment, credential rotation, eradication or recovery outcome is asserted. Operational compilation/schema/coverage validation remains required before adopting the detections.

## Manifest accounting, links and version integrity

- **70 rows, 70 unique IDs, filenames, absolute paths and recorded SHA-256 values.** IDs are exactly EV-001 through EV-070, hashes have valid SHA-256 syntax, and filenames are strictly chronological.
- First/last filenames match preservation notes: `Screenshot From 2026-11-03 00-54-22.png` through `Screenshot From 2026-11-04 21-24-13.png`. Every original path exists as a regular file; all 70 recorded sizes and UTC modification timestamps match current metadata.
- The preservation selection is the inclusive filename range in `evidence/PRESERVATION_NOTES.md:19`. Exactly 70 regular matching screenshots occur in that range, and their names match the manifest exactly. Other screenshots in the shared directory are outside this selection and were not examined or introduced as incident evidence.
- All 70 remain accounted for; only seven selected originals were freshly hash/transform checked in this review. Historical full-collection hash results at TF:458 and `report/TECHNICAL_FINDINGS_QA.md:25–29` retain their original scope/date.
- All cited evidence IDs and original filenames occur in the source manifest. The technical report cites ten distinct source IDs; repeated views do not add events. EV-067's lab-answer fields remain explicitly excluded as packet/credential proof at ER:111 and TF:456. Unrelated screenshots are not embedded as incident evidence.
- **53 existing internal relative document/image links resolve**, including links in both historical QA files and all seven technical-report image references. Original absolute paths and derivative-manifest filename references also resolve. External HTTP links were not tested online. Relative structure must be preserved when assembling or relocating the report; standalone exports may require asset embedding or path adaptation.
- SHA-256 hashes of all **18 pre-existing project files** were compared before and after this review; all remain unchanged. Only `report/FINAL_CONSISTENCY_QA.md` was added. No original screenshot was written, and no source document, manifest, timeline, mapping or figure was changed.

### Reviewed document versions

| Source | SHA-256 of reviewed version |
|---|---|
| `report/EXECUTIVE_SUMMARY.md` | `1260a3376ba3cb42eb72c4c6983c0670616c2589b5982769db633b266d851d89` |
| `report/TECHNICAL_FINDINGS.md` | `2f29f1ea41ed81652b4087407c43f728425e324f8c9cbfad64126f40659a7456` |
| `report/TECHNICAL_FINDINGS_QA.md` | `1e6269d1096b802bff12b66d77d1c8f6feec1011d58f4679a779f3ea1043a72f` |
| `report/DETECTION_AND_RESPONSE.md` | `71bd85872d95dbe1684b084fd108aeb0d1ce40326da258e7621871cab259601a` |
| `report/DETECTION_AND_RESPONSE_QA.md` | `e9e66cef840d631ca31908d9dd5b608f09aecdc7474c84e1224210b2b511eef1` |
| `evidence/TECHNICAL_EVIDENCE_REGISTER.md` | `ff3883783e6faa5858b572f7b4e967077b533e74477f101b7dde9964e2c105f8` |
| `evidence/ATTACK_TIMELINE.md` | `ae2dd5e4845945e6fbea540470845e33efa9f797f8265f440da851665b25b805` |
| `evidence/MITRE_ATTACK_MAPPING.md` | `09ecd51e52babdb6094e6d2ebfe23951b95fc5a2c1ae09488ef8f1c85fc26a68` |
| `evidence/SCREENSHOT_MANIFEST.csv` | `a59500cced4eaf6e9875e34fd2b958778549ca6e1117e71b4560ea3618f10721` |
| `evidence/PRESERVATION_NOTES.md` | `cf67aefb6c71efae1dc1420693df2bf8222db612530ab7b2e20160ce2a74193c` |

The historical D&R QA explicitly reviewed **439 lines / SHA-256 `7b144fd0051bd754cbbc7bb743e5fecd20ac24f8453cb5d2b56f52ff92f1a117`** (`report/DETECTION_AND_RESPONSE_QA.md:3`). Current D&R has **464 lines** and the different hash above because its authorized corrections were applied. That difference is expected revision history, not evidence corruption. Current TF has **462 lines** and explicitly records its earlier QA corrections at TF:460. Process-history statements about what was or was not created in individual prior revisions are not a current inventory of the assembled package.

## Final integration-readiness checklist

- [x] All ten requested documents reviewed together; current source versions recorded.
- [x] Seven findings preserved with correct primary/supporting evidence roles, selected frames, recorded Time values and timeline entries.
- [x] Seven report figures verified against original IDs/filenames/hashes, derivative hashes, declared transformations and visible caption support.
- [x] All 70 originals accounted for within the preservation selection; no missing manifest entry or unrelated report figure.
- [x] Response priority, conditional impact, observation/interpretation confidence and undetermined incident severity remain separate.
- [x] No submitted command or HTTP 200 is upgraded to confirmed execution, credential recovery, startup, escape or compromise.
- [x] Privileged-only Docker and root-bind/chroot requests remain separate, with qualified daemon/containment context.
- [x] Seven ATT&CK assignments/statuses/confidence levels remain consistent, including tentative Moderate T1565.001.
- [x] Administrative account/token monitoring remains preventive, not a new established finding.
- [x] Executive scope/attribution are appropriately limited; recommendations/playbook actions are not represented as lab outcomes.
- [x] Both earlier technical-report corrections and all three required detection-report corrections verified closed; historical QA conclusions reconciled here.
- [x] Existing internal links/images resolve; protected project-file hashes unchanged; only this review file added.
- [x] No PCAP investigation, original screenshot-content audit, query deployment, commit, publication or upload performed.

**Assembly guidance:** Preserve this final closure record with the historical QA reviews, retain source/figure traceability and all material caveats, and check eventual export legibility/asset packaging. No final report assembly or README was created during this review.

**Unresolved incident questions, not integration blockers:** authorization and actor identity; effective vulnerability/CVE-specific effects; complete capture/time basis and request-response linkage; deployed/activated JSP artifacts; command/file results and genuine credential exposure; Docker startup/configuration, daemon identity, initial containment and actual host access; affected scope/business impact. These require additional evidence before stronger incident conclusions.

**Operational prerequisites, not claims of completed testing:** configure/validate actual endpoint and custom-table schemas, parsers, lineage/approval baselines, Docker inspection/lifecycle correlation, telemetry completeness, clocks, scheduling/deduplication and response ownership. Compile and test adopted rules in the intended platform before deployment. Examples remain proposed and untested.

**Final disposition: PASS — ready for integration into a final report within the explicitly limited screenshot-supported scope.** No successful incident outcome or conclusive incident-severity classification is established.
