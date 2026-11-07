# JetBrains TeamCity — Independent Technical Findings QA

Review date: **2026-11-07**. Reviewed document: [TECHNICAL_FINDINGS.md](TECHNICAL_FINDINGS.md). **Disposition: requires limited classification and wording corrections before final reporting.**

## Overall assessment

The report is technically careful and substantially supported by the selected screenshots. It consistently distinguishes requests from outcomes, preserves the two distinct Docker commands, and follows the latest seven-technique ATT&CK mapping. No invalid evidence ID, mismatched original filename, incorrect registered packet number, substituted screenshot, undeclared derivative pixel change, or exposed credential/Bearer-token value was found in the report and its seven embedded figures. None of the seven captions claims successful execution or compromise.

Two presentation issues require correction: the report labels defensive response priority as “severity” without separately recording evidence-supported incident severity, and F-001's heading “Vulnerability Exposure” can imply a vulnerable configuration that the body explicitly leaves unverified. These are clarity defects, not evidence corruption or confirmed exploit overclaims in the detailed analysis.

**Retain the current Medium/High values as provisional response priorities after making that distinction explicit.** F-002, F-006 and F-007 justify High priority because their submitted capabilities could enable broad access. Their evidence does **not** justify reporting a confirmed High-impact incident. Incident severity remains **undetermined**, rather than automatically Medium, Low or High, because execution, authorization, affected assets and operational impact are unresolved. The same outcome limitation applies to the other findings; F-001 additionally establishes actual version disclosure, but its security impact is not established.

After the two corrections below, the report can serve as a final **screenshot-supported assessment of disclosure and attempted activity**, with outcomes expressly unverified. Additional evidence would be necessary to report successful exploitation, installation, command execution, credential compromise, file modification, container startup or escape.

## Review basis and independent checks

The latest local versions of all five requested documents were read:

- [TECHNICAL_EVIDENCE_REGISTER.md](../evidence/TECHNICAL_EVIDENCE_REGISTER.md).
- [ATTACK_TIMELINE.md](../evidence/ATTACK_TIMELINE.md).
- [MITRE_ATTACK_MAPPING.md](../evidence/MITRE_ATTACK_MAPPING.md).
- [SCREENSHOT_MANIFEST.csv](../evidence/SCREENSHOT_MANIFEST.csv).
- [PRESERVATION_NOTES.md](../evidence/PRESERVATION_NOTES.md).

The [derivative manifest](figures/DERIVATIVE_MANIFEST.csv) and all seven embedded PNGs were also reviewed. Each embedded image was visually inspected. All 70 original screenshots were read for size/hash verification using `O_NOATIME`; read-time checks found no changes to file identity, size, access time, modification time or change time. The seven figures were compared with their specified originals in memory, including every pixel outside the declared redaction boxes.

Checks established:

- **70/70** originals match the preservation manifest's file sizes and SHA-256 hashes.
- **10 distinct report evidence IDs** are valid: EV-008, EV-014, EV-060, EV-061, EV-062, EV-065, EV-066, EV-068, EV-069 and EV-070. All **11 explicit ID/filename occurrences** match the manifest.
- **13 local document/image links** resolve, including all seven embedded image paths.
- **7/7 derivatives** match their own hashes, source IDs, original filenames, source hashes and crop dimensions. No pixels differ outside the declared masks. All are RGB PNGs with no PNG metadata reported by the image parser.
- Encoded bodies independently count to **6, 26, 43 and 62 bytes**, respectively, for `ls`, the file read, privileged Docker deployment and the host-root mount/chroot request. The 99-byte write count was checked against the screenshot/register, not reconstructed from secret values.
- The report's packet, stream, reassembly and Time references were compared with the register and timeline. No discrepancy was found. This is screenshot/document verification, not independent source-capture validation.
- Visual inspection and text screening found no unredacted credential assignments, Bearer-token values or JWT values in the report/embedded figures. Original evidence is preserved with its original content; this finding does not certify raw originals as suitable publication figures.

The register and mapping inherit prior screenshot observations; agreement between those documents alone is not independent corroboration of execution. This QA independently checked the embedded visuals and their source identity, but did not inspect a source PCAP, full archive, server logs or filesystem artifacts. Unembedded supporting views EV-060, EV-061 and EV-069 were hash/reference checked; their behavioural role remains inherited from the register. No fresh vendor or MITRE web retrieval is claimed. ATT&CK consistency was assessed against the latest supplied mapping and its disclosed verification basis.

## Severity recommendations

Four dimensions must remain separate: **potential impact if successful**, **evidence-supported incident severity**, **confidence in the observed behaviour**, and **confirmation of execution or compromise**. A high-confidence request can demand urgent investigation while leaving its outcome entirely unverified. Absence of outcome evidence does not demonstrate either failure or low impact.

| Finding | Current rating | Independent recommendation | Evidence-supported incident classification |
|---|---|---|---|
| F-001 | Medium | **Medium response priority** for version/mitigation validation and suspicious routing review. Version disclosure by itself would usually merit Low informational severity; the unusual request context supports the higher investigative priority. | Version disclosure observed; vulnerable configuration and exploitation unverified. Incident severity undetermined. |
| F-002 | High | **High response priority** for attempted placement of a reusable command interface. Do not label it a confirmed High-severity installation or compromise. | Suspicious upload submission observed; webshell-placement interpretation tentative; acceptance/deployment unverified. Incident severity undetermined. |
| F-003 | Medium | **Medium response priority** for a concrete discovery request. No listing or additional accessible data supports escalation on this finding alone. | Directory-discovery command submission observed; execution unverified. Incident severity undetermined. |
| F-004 | Medium | **Medium response priority** for a targeted file-read request. A sensitive-looking filename does not establish stolen credentials or justify High credential-compromise severity. | Local-file read attempt observed; existence, contents and disclosure unverified. Incident severity undetermined. |
| F-005 | Medium | **Medium response priority** for explicit shell invocation and intended file creation/overwrite. No operational dependency or realized integrity effect supports High impact. | Shell/write request observed; stored-data manipulation tentative; filesystem/account changes unverified. Incident severity undetermined. |
| F-006 | High | **High response priority** for requested privileged container deployment. The expanded privileges warrant urgent validation; they do not establish deployment or host escape. | Privileged-container command submission observed; startup and privilege grant unverified. Incident severity undetermined. |
| F-007 | High | **High response priority** for the explicit host-root bind mount and `chroot`. Broad requested filesystem access supports urgency even without `--privileged`; Critical is unsupported. | Host-filesystem access request observed; escape interpretation tentative; actual access/compromise unverified. Incident severity undetermined. |

These recommendations retain the values only under the report's stated **defensive-priority model**. They are not endorsements of seven measured incident severities. If a final-report template permits only an incident-severity field, enter **Undetermined — impact and execution unverified**, and carry the High/Medium priority in a separate field. Do not automatically replace the three High values with Medium solely because successful execution is missing. No CVSS assessment is supported by this evidence.

## Finding-by-finding review

### F-001 — TeamCity identification and possible vulnerability exposure

**Evidence and figure:** EV-008 is the correct primary source for [Figure F-001](figures/F-001_EV-008.png). EV-014 is valid later upload context only. Frame **24711**, stream **364**, Time **1054.290142**, version **2023.11.3**, build **147512**, HTTP 200 and the displayed HTTP Date agree with the register/timeline and visible figure.

The screenshot also visibly contains `GET /hax?jsp=/app/rest/server;.jsp HTTP/1.1`. The report accurately identifies this as a new visibility clarification, while leaving the request frame, authorization and precise pairing unresolved. It does not silently promote the inherited exploitation hypothesis. The figure supports an advertised version and unusual routing context, not the effective patch state or a successful authentication bypass. The displayed public Host value and packet destination alone do not establish the investigated service's exposure controls or capture topology.

**Potential impact:** A genuinely vulnerable and reachable CI application could permit substantial unauthorized access; scope would depend on the service's privileges and reachable build/deployment assets. This conditional risk is not established by a banner.

**Confidence and outcome:** High for the advertised values and displayed references; Low for T1190/CVE-specific exploitation. No exploitation or compromise is confirmed. Medium investigation priority is defensible in the combined request context; a confirmed vulnerable-configuration or incident-severity label is not.

**Required correction:** Qualify the title, for example **“TeamCity Version Disclosure and Suspected Vulnerability Exposure”** or **“TeamCity Version Disclosure and Suspicious REST Routing.”** Preserve the existing CVE hypothesis and caveats; do not imply that 2023.11.4 is a current remediation target. The body already recommends a currently supported, vendor-fixed release.

### F-002 — Suspicious plugin upload and possible webshell placement

**Evidence and figure:** EV-014 correctly supplies [Figure F-002](figures/F-002_EV-014.png), frame **24825**, stream **364**, Time **1071.315015**. EV-062 validly supplies later matching-path context, not upload acceptance. The figure shows the clipped upload path, multipart archive name **`NSt8bHTg.zip`**, JSP resource text and **`request.getParameter("cmd")`**. The foreground method is clipped; the report correctly attributes POST to the register rather than pretending that fragment displays it.

A JSP accepting a `cmd` parameter and later requests to its matching path support a suspicious command-interface interpretation. Parameter handling alone is not a full code audit or proof that a process is launched. The selected screenshot does not show an acceptance response, installed plugin inventory, deployed JSP artifact or activation record. Its caption correctly describes submission.

**Potential impact:** A functioning reusable server-side command interface could expose the CI service's accessible files, credentials and downstream systems. High potential impact is reasonable; broader privileged compromise depends on access that has not been demonstrated.

**Confidence and outcome:** High for upload content and displayed references; Moderate for attempted webshell placement. Acceptance, storage, installation, activation, persistence and command execution are all unverified. **Retain High response priority** because validating an attempted reusable interface is urgent, while recording incident severity as undetermined. Matching later URIs do not close the deployment gap.

**Corrections:** Apply the severity/priority separation in R-001. No evidence-reference or caption correction is required. Keep T1505.003 tentative.

### F-003 — `ls` submission and directory-discovery attempt

**Evidence and figure:** EV-062 correctly supplies [Figure F-003](figures/F-003_EV-062.png). EV-060/EV-061 are valid repeated supporting views; EV-014 is valid component context. Frame **25572**, Time **1122.563990**, the JSP path, source **23.158.56.196**, destination **172.31.25.119**, and reassembly **25566 (527) + 25572 (6) = 533 bytes** match the register. Packet bytes and the expanded form both show **`cmd=ls`**. No stream ID is invented.

**Potential impact:** A successful listing could disclose filenames and guide follow-on discovery. The direct action has a narrower demonstrated purpose than installation of a reusable interface or host-root access. Unknown downstream use cannot establish High impact for this listing request.

**Confidence and outcome:** High for submission/discovery semantics; Moderate for suspected webshell use. No returned listing, process execution, exit status or working directory is established. Medium response priority is appropriate. The screenshot/caption do not claim a successful listing.

**Corrections:** Apply R-001. Retain T1083 as an observed attempt and T1505.003 as tentative. Do not add T1059.004 to `ls` alone: this request does not identify an interpreter.

### F-004 — Attempted read of `/tmp/Creds.txt`

**Evidence and figure:** EV-065 correctly supplies [Figure F-004](figures/F-004_EV-065.png), frame **26895**, Time **1524.276831**, and reassembly **26889 (528) + 26895 (26) = 554 bytes**. The 26-byte form body **`cmd=cat+%2Ftmp%2FCreds.txt`** and expanded **`cat /tmp/Creds.txt`** agree. No stream ID is established.

The figure shows a request and an analyst search field. It contains no returned file contents. The report correctly states that search text is not evidence of stored credentials. This read precedes F-005's write and cannot validate a later modification.

**Potential impact:** Reading real service-accessible secrets could compromise affected identities, depending on validity and scope. The file could instead be absent, inaccessible or contain test/noncredential data. Its name does not establish either sensitive content or High impact.

**Confidence and outcome:** High for command/path; Moderate for possible collection intent. File existence, access, execution, content receipt and credential compromise are unverified. Medium response priority is appropriate.

**Corrections:** Apply R-001. No technique or formal tactic is assigned in the latest mapping; preserve that treatment. Do not restore T1552.001 based on the filename or lab answer fields.

### F-005 — Attempted credential-labelled file write

**Evidence and figure:** EV-066 correctly supplies [Figure F-005](figures/F-005_EV-066.png), frame **31123**, Time **1721.175300**, TCP payload **99 bytes**, and reassembly **31117 (528) + 31123 (99) = 627 bytes**. The visible structure requests **`bash -c`**, **`echo`** and redirection to **`/tmp/Creds.txt`**. Both decoded credential occurrences and the packet-byte pane are masked. The report correctly distinguishes the redacted transcription's length from the original payload count. Frame **31124**, Time **1721.175329**, is a client POST, not a confirming response.

Shell `>` would create an absent file or truncate/overwrite an existing file if execution and permissions allowed. Writing username/password-labelled text is not an account-management operation and does not prove a password change. Prior contents, a consuming application, write success and later readback are missing.

**Potential impact:** Successful modification could affect integrity if an operational process relied on this file. That dependency and any resulting consequence are hypothetical; fixture/test-data creation is also possible. A local text write alone does not support High business impact.

**Confidence and outcome:** High for the explicit shell/write structure; Moderate for attempted stored-data manipulation. No execution, creation, modification, account change or credential use is confirmed. Medium response priority is appropriate.

**Corrections:** Apply R-001. Keep T1059.004 as an observed attempt and restored T1565.001 as tentative. A successful write, even if later proven, would still require context to establish an Impact objective.

### F-006 — Privileged Docker deployment request

**Evidence and figure:** EV-068 correctly supplies [Figure F-006](figures/F-006_EV-068.png); EV-069 remains a repeated request view, and EV-070 supplies stream membership only. Frame **32002**, Time **2039.893932**, and reassembly **31996 (528) + 32002 (43) = 571 bytes** agree. The complete 43-byte body decodes to **`docker run --rm -it --privileged ubuntu`**. Stream **601** remains a Moderate-confidence association from the later filtered view.

This request contains **no host-root bind mount or `chroot`**. `--privileged` requests expanded container privileges; it does not establish that they were granted or that a boundary was crossed. Docker availability, daemon access, image/runtime conditions and noninteractive terminal handling could prevent startup. Frame **32003**, Time **2039.893977**, is another client POST. HTTP 200 rows **32008 (2039.940450)** and **32010 (2039.940483)** do not establish Docker success; bodies and pairing are unverified.

**Potential impact:** Granted privileged operation on a typical Linux Docker host can materially weaken confinement and broaden capabilities/device access. Actual host risk depends on the daemon/runtime configuration and initial permissions. This is materially more concerning than ordinary discovery, even without proven startup.

**Confidence and outcome:** High for the command/deployment semantics; Moderate for stream association. No Docker execution, container startup, privilege escalation, escape or host compromise is confirmed. **Retain High response priority** for validating requested expanded privileges; incident severity is undetermined. Do not lower it automatically because evidence of startup is missing, or escalate it to Critical from the flag alone.

**Corrections:** Apply R-001. Keep T1610 as an observed attempt. Do not assign T1611 to this privileged-only command; the latest mapping confines that tentative interpretation to F-007.

### F-007 — Docker host-root bind mount and `chroot` request

**Evidence and figure:** EV-070 correctly supplies [Figure F-007](figures/F-007_EV-070.png). Stream **601**, footer **Packet 32111**, packet-list Time **2065.593291**, the 62-byte body, and following HTTP headers agree with the register/timeline. The background selection remains **32010**; it must not replace the footer's command reference. The foreground body decodes to **`docker run --rm -it -v /:/host ubuntu chroot /host`**. Its request line is outside the viewport; the later visible POST belongs to subsequent stream context.

The command requests the **Docker daemon host's** root at `/host`, ordinarily read/write absent a read-only option, then a changed process root through `chroot /host`. The daemon host could differ from the TeamCity/client host. Starting containment, daemon identity and effective permissions are unknown. `chroot` does not itself demonstrate escape from all namespaces. This distinct command has **no `--privileged` flag**.

The following HTTP 200 headers advertise **Content-Length: 4**, with HTTP Date **Sun, 30 Jun 2024 08:19:40 GMT**. No readable output or response-frame identifier is visible. Four advertised bytes cannot be interpreted as an exit status, successful shell output, mount success or a host-access confirmation.

**Potential impact:** A successful writable host-root mount with sufficient access could expose or alter host configurations, application data and secrets. The explicit scope supports High concern; Critical would require corroborated extensive privileged impact and scope, which are absent.

**Confidence and outcome:** High for command text and stream number; Moderate for frame/body association and the overall T1610/T1611 assessments. No startup, mount, `chroot`, escape, host read/write or compromise is confirmed. **Retain High response priority**, with incident severity undetermined. This recommendation rests on the requested host-filesystem scope, not the nearby status code or the earlier privileged flag.

**Corrections:** Apply R-001. Preserve the qualified footer association and separate Docker findings. Keep T1610 as an observed attempt and T1611 tentative; no evidence-reference/caption repair is required.

## ATT&CK consistency

All formal mappings match the latest mapping document, including techniques, assessed tactics, status and confidence. **No technique additions or removals are recommended.**

| Technique | Finding(s) | Latest mapping treatment verified in the report | QA reasoning |
|---|---|---|---|
| **T1190 — Exploit Public-Facing Application** | F-001 | Initial Access hypothesis; tentative; Low confidence | Banner and unusual route do not establish authorization bypass, public-facing deployment or successful exploitation. Keep the hypothesis qualified. |
| **T1505.003 — Server Software Component: Web Shell** | F-002, F-003 | Persistence interpretation; tentative; Moderate confidence | Uploaded command-handling JSP fragment and matching later URI support attempted placement/use, not deployment, functioning access or persistence. |
| **T1083 — File and Directory Discovery** | F-003 | Discovery; observed attempt; High confidence | `ls` explicitly requests discovery; no listing establishes completion. |
| **T1059.004 — Command and Scripting Interpreter: Unix Shell** | F-005 | Execution; observed attempt; High confidence | Explicit `bash -c` identifies the interpreter. Do not infer it from `ls`, `cat` or Docker command text alone. |
| **T1565.001 — Data Manipulation: Stored Data Manipulation** | F-005 | Impact; tentative attempted manipulation; Moderate confidence | `>` indicates intended creation/overwrite. Operational purpose, successful change and achieved Impact remain unverified. The restored mapping is retained. |
| **T1610 — Deploy Container** | F-006, F-007 | Execution; observed attempts; High command-fit confidence in F-006, Moderate overall confidence in F-007 | Both distinct `docker run` submissions fit attempted deployment. Neither proves creation/start; F-007's frame association is indirect. |
| **T1611 — Escape to Host** | F-007 only | Privilege Escalation interpretation; tentative; Moderate confidence | Host-root binding plus `chroot` supports the attempted host-access interpretation, subject to starting containment/daemon context. The privileged-only F-006 request does not justify this mapping. |

F-004 correctly has **no technique assigned**. T1592.002, T1552.001 and T1105 remain absent as formal assignments. The report's references to excluded IDs explain their exclusion rather than adding techniques. Seven unique technique IDs do not represent seven successful techniques; multiple mappings describe aspects of the same event. The selected seven-event sequence remains **24711 → 24825 → 25572 → 26895 → 31123 → 32002 → 32111**.

## Evidence inconsistencies and unresolved associations

**No factual reference inconsistency was found in the reviewed report/figures against the latest evidence documents.** In particular, all main packet numbers, auxiliary request/response-row references, reassembly segment numbers and numeric Time values agree. The report does not extend streams 364 or 601 to frames whose stream IDs are unestablished.

The following are existing evidence limitations, not newly discovered transcription errors:

- EV-008 visibly adds a GET request line to the inherited account, but its separate request frame, precise pairing and authorization state remain unresolved. The report explicitly discloses this clarification.
- Streams for **25572, 26895 and 31123** remain unestablished. Nearby **31124** and **32003** are client requests with unopened/unverified bodies and streams.
- **32008/32010** have packet-list status evidence, not inspected shell-result evidence. F-007's following response has no visible frame identifier or readable body.
- **32111** is associated through the stream footer, not expanded request details; **32010** is the background selection. Confidence correctly remains Moderate for that association.
- EV-060/EV-061/EV-062 and EV-068/EV-069 are repeated views of their respective events. They do not establish additional commands or independent execution outcomes.
- The earlier file read cannot confirm the later file write. Search inputs and lab answers are not packet, credential-content or filesystem proof.
- Numeric Wireshark Time values do not establish their configured mode/reference or absolute event timestamps. HTTP Dates and screenshot filename dates remain distinct.

## Embedded screenshot and caption review

| Figure | Source ID and derivative | What is visibly supported | Presentation/caption disposition |
|---|---|---|---|
| F-001 | EV-008; `F-001_EV-008.png` | XML version/build, HTTP 200, frame 24711, stream 364 and unusual GET context | Accurate. No exploitation claim. Selected version and packet references remain legible. |
| F-002 | EV-014; `F-002_EV-014.png` | Upload path, archive/JSP text, `cmd` parameter handling and frame/stream references | Accurate. Clipped method is disclosed in the prose. Authentication/CSRF mask preserves the relevant archive/code evidence. |
| F-003 | EV-062; `F-003_EV-062.png` | Selected POST, `cmd=ls`, expanded value and reassembly | Accurate. No directory-listing output is asserted. |
| F-004 | EV-065; `F-004_EV-065.png` | Selected file-read command, encoded bytes, reassembly and analyst search field | Accurate. Caption explicitly prevents treating the search term as file contents. |
| F-005 | EV-066; `F-005_EV-066.png` | Selected frame, shell/redirection structure, target path and reassembly | Accurate. Both decoded secret occurrences and encoded pane are masked. Caption establishes submission, not a file change. |
| F-006 | EV-068; `F-006_EV-068.png` | Privileged command, 43-byte body, reassembly and nearby status rows | Accurate. Header-byte mask preserves command bytes. Caption correctly attributes stream membership to EV-070 separately. |
| F-007 | EV-070; `F-007_EV-070.png` | Root mount/chroot body, stream/footer, different background selection and response headers | Accurate. Explicitly states no readable output; does not confuse HTTP 200 with shell success. |

The seven figures directly support their associated findings. Cropping removes unrelated desktop material; opaque masks are identifiable editorial changes. No source substitution, residual readable secret value or hidden PNG metadata was found. Captions preserve the distinction between originals and derivatives, and source filenames/hashes remain traceable.

At native resolution the decisive text is readable. Five figures are 1920×802 pixels and two are 1512×759; a narrow fixed-width export could make packet/code text small. As an optional presentation improvement, preserve access to full-size images and check command/frame legibility in any eventual export. Further cropping should retain the relevant packet/stream references and avoid revealing masked values. There is no screenshot replacement blocker in the current Markdown.

The repeated limitations and the final drafting-process paragraph make the report longer than necessary, but its structure is professional and coherent. Condensing duplicate caveats and moving process history to an appendix are optional editorial improvements, not prerequisites for evidence accuracy.

## Required corrections

### R-001 — Separate response priority from incident severity

**Location:** `TECHNICAL_FINDINGS.md:23`, especially the model at line 25, summary table at line 36, and each finding's severity lead-in.

The report deliberately defines severity as defensive priority; this is a documented choice, not an unexplained High-impact assertion. Nevertheless, final readers can extract “F-002 — High” without the model and mistake it for evidence-supported incident severity. Renaming only the explanatory paragraph would leave the finding headings vulnerable to that interpretation.

**Required change:** Label the existing values **“Provisional response priority”** consistently in the model, summary table and finding lead-ins. Add an explicit **“Incident severity: undetermined; execution/compromise and operational impact unverified”** statement or column. Distinguish F-001's observed disclosure from unverified vulnerability/exploitation. Keep observation/interpretation confidence separate. Preserve High priority for F-002/F-006/F-007 with the finding-specific rationale above.

**Acceptance criterion:** A reader using the summary or any isolated finding can distinguish urgency, conditional impact and confirmed outcome without consulting a distant caveat. No High/Medium value is presented as a confirmed incident-impact rating.

### R-002 — Qualify F-001's vulnerability heading

**Location:** `TECHNICAL_FINDINGS.md:48`.

“TeamCity Server Identification and Vulnerability Exposure” can imply a proven vulnerable configuration, while the body correctly describes advertised software values and a tentative exploitation hypothesis.

**Required change:** Use a title that states disclosure/suspicious routing or explicitly qualifies vulnerability exposure as suspected. Do not change the evidence IDs, packet values, tentative T1190 mapping or existing exploitation limitations.

**Acceptance criterion:** The heading alone does not assert confirmed vulnerability, CVE exploitation or unauthenticated access.

No changes to the evidence register, timeline, ATT&CK mapping, preservation notes, original screenshots or manifests are required or authorized by this QA. No figure or caption correction is required by the checks performed.

## Publication blockers and final disposition

**Current blockers to final-report sign-off:** R-001 and R-002. These are limited classification/wording corrections. No missing screenshot, invalid evidence reference, preservation-hash discrepancy, credential exposure, ATT&CK mismatch or unsupported success claim in the detailed analysis was found.

**Blockers to stronger incident claims:** Full packet/response linkage and authorization evidence are needed for exploit conclusions; deployed artifacts/audit records for installation; process/response/exit evidence for command execution; file state/readback for collection or modification; and Docker/runtime/host telemetry for container startup, host access or escape. Asset scope and operational consequences are needed for an incident-severity rating. These gaps do not independently prevent a final, expressly limited screenshot-based assessment after R-001/R-002 are corrected.

**Final determination: technical findings require corrections before final reporting.** The necessary changes concern severity semantics and F-001's heading, rather than rewriting the evidence-based technical analysis. Successful exploitation or compromise remains unconfirmed throughout.

This review created only this QA document in the investigation directory. The original report, seven figures, derivative manifest, five evidence documents and original screenshots were not modified. Protected-input hashes were checked against the QA baseline, and original screenshot hashes against the preservation manifest. Nothing was published or sent externally.
