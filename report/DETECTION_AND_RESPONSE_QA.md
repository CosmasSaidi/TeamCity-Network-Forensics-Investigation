# JetBrains TeamCity — Independent Detection and Response Technical QA

Review date: **2026-11-07**. Reviewed document: [DETECTION_AND_RESPONSE.md](DETECTION_AND_RESPONSE.md), **439 lines**, SHA-256 `7b144fd0051bd754cbbc7bb743e5fecd20ac24f8453cb5d2b56f52ff92f1a117`.

## Overall assessment: PASS WITH CORRECTIONS

The document preserves the evidence boundaries, all seven investigation findings and the latest seven-technique ATT&CK mapping. It consistently treats the network material as submitted requests, separates privileged Docker deployment from host-root mounting/chroot, leaves credentials and tokens undisclosed, and retains **undetermined incident severity**. Administrative account/token monitoring remains explicitly preventive. The seven response stages are practical and do not claim actions were performed during the lab.

Three **Medium** corrections are required before integrating the document's logic into operational procedures: explicit Boolean grouping in D-004/D-010; more accurate labels for Q-002's command-text matches; and correction of Q-005's configured-versus-mounted terminology and unknown-data handling. No Critical or High issue was identified. No definite KQL syntax error was identified by static review under the stated schemas, but this is not a live compilation or tenant-compatibility certification.

**Review method and limits:** The original document and the five source-of-truth documents were read: [technical findings](TECHNICAL_FINDINGS.md), [evidence register](../evidence/TECHNICAL_EVIDENCE_REGISTER.md), [timeline](../evidence/ATTACK_TIMELINE.md), [ATT&CK mapping](../evidence/MITRE_ATTACK_MAPPING.md) and [executive summary](EXECUTIVE_SUMMARY.md). Review covered every executable line in all six KQL examples, the eleven detection entries, collection guidance and all response stages. No PCAP, original screenshot or presentation figure was reopened, rehashed or audited. No KQL, audit rule or response action was executed. Attempts to retrieve Microsoft schema/KQL and Docker references failed with DNS resolution errors; no fresh online verification is claimed. The assessment relies on the supplied evidence and static review of known KQL/native schema conventions plus the explicitly assumed custom contracts.

All line references below refer to this reviewed version of **DETECTION_AND_RESPONSE.md**, not to the QA file. Issue ranks concern detection implementation and reporting clarity; they are not incident-severity ratings. The original document was left unchanged. The requested QA file was written after completing the read-only review.

## 1. Ranked findings

| Rank | ID | Issue | Exact original section and lines | Disposition |
|---|---|---|---|---|
| Critical | — | None identified | — | — |
| High | — | None identified | — | — |
| **Medium** | **QA-001** | Ambiguous Boolean grouping can bypass event-type or approval guards | **“D-004 — Shell processes associated with TeamCity”**, line **73**; **“D-010 — Suspicious administrative account, role or token creation”**, line **133** | Required correction |
| **Medium** | **QA-002** | A substring match is labelled as a requested Docker privilege, although it may be a container-command argument | **“Q-002 — Docker/chroot process leads (D-006–D-009)”**, lines **203–211**, especially **204–207** | Required correction |
| **Medium** | **QA-003** | `HostRootMounted` conflates configuration with an established mount and collapses missing mount data into false | **“Q-005 — Effective privileged configuration or root bind mounts (D-007/D-008)”**, lines **282–295**; **“3.3 Sentinel normalized custom tables — explicit assumptions”**, lines **247, 253** | Required correction |
| **Low** | **QA-004** | One-hour hunting windows need explicit adaptation to the proposed scheduled-rule window | **“3.5 Correlation, alert deployment and validation”**, line **341**; query time filters at **179, 200, 226, 260, 280, 302** | Optional documentation improvement; deployment prerequisite |
| **Low** | **QA-005** | Legacy audit watch templates should include a modern rule alternative and clearer deployment constraints | **“3.4 Linux auditd, Sysmon and runtime collection details”**, lines **315–329**, especially **321–324** | Optional improvement |

### QA-001 — Medium: make event and approval guards explicit

**Evidence of the issue:** D-004 combines service-account matching, ancestry and lack of approval without parentheses. A conventional `AND`-before-`OR` translation can allow the service-account branch to bypass the approval check. D-010 similarly mixes identity event types, approval and actor novelty: an unexpected actor branch can match without any identity-change event. The prose has a reasonable intent, but the pseudocode is insufficiently precise for translation into a rule.

**Suggested replacement pseudocode — untested:**

```text
# D-004: proposed, untested; an event-type guard applies to both branches.
IF IsUnixShellProcessStart
   AND (TeamCityServiceIdentityMatch OR VerifiedTeamCityAncestor)
   AND ApprovalState IN ("Unknown", "NotApproved")
THEN create a shell-activity investigation candidate.

# D-010: preventive control only; no new incident event is asserted.
IF NormalizedAction IN ("user_created", "admin_role_granted", "token_created")
   AND (ApprovalState IN ("Unknown", "NotApproved") OR UnexpectedActorContext)
THEN create an identity-change investigation candidate,
     retaining OperationResult as success, failure or unknown.
```

Unknown approval is an investigation lead, not proof of unauthorized activity. A failed creation attempt must remain distinguishable from a server-confirmed inventory change. This suggestion changes no case finding or ATT&CK assignment.

**Acceptance criterion:** Every logical branch requires the intended event type; approval/actor conditions apply in their intended scope. Do not express precedence only through narrative punctuation.

### QA-002 — Medium: Docker flag text does not establish option position or effect

**Evidence of the issue:** Q-002 searches the entire `ProcessCommandLine` for flag-shaped text. For example, the hypothetical benign command `docker run ubuntu echo --privileged` would satisfy the privilege regex, even though the text is an argument to the container command. Likewise, `docker run ubuntu echo -v /:/host` can satisfy the root-bind regex without configuring a mount. Duplicate/conflicting flags, quoting, wrappers and truncation further limit interpretation. These are illustrative counterexamples, not observed incident commands or test results.

The surrounding text correctly calls the results indicators, and `RootBindCandidate` already signals uncertainty. The stronger name **`PrivilegedRequested`** nevertheless attributes meaning that the regex has not established. Also, `ChrootProcess` detects the literal process filename; it does not detect a `chroot` argument embedded in a Docker entry command or confirm a successful syscall.

**Suggested replacement KQL — untested, same native table assumptions:**

```kusto
// PROPOSED AND UNTESTED: text indicators, not parsed Docker configuration.
let CiClients = dynamic(["replace_with_ci_client_hostname"]);
DeviceProcessEvents
| where Timestamp > ago(1h)
| where DeviceName in~ (CiClients)
| where ActionType == "ProcessCreated"
| where FileName in~ ("docker", "docker.exe", "chroot")
| extend CommandLineAvailable = isnotempty(ProcessCommandLine)
| extend PrivilegedFlagTextPresent = ProcessCommandLine matches regex
    @"(?i)(^|\s)--privileged(?:=true)?(\s|$)"
| extend RootBindFlagTextPresent = ProcessCommandLine matches regex
    @"(?i)(^|\s)(-v\s*|--volume(?:=|\s+))/:/"
| extend ChrootProcess = FileName =~ "chroot"
| project Timestamp, DeviceId, DeviceName, ReportId,
          FileName, AccountName, InitiatingProcessFileName,
          CommandLineAvailable, PrivilegedFlagTextPresent,
          RootBindFlagTextPresent, ChrootProcess
```

`CommandLineAvailable` means nonempty, not complete or unredacted. To call an option **requested**, use an argument-aware parser that distinguishes Docker subcommand options from image/entry-command arguments, handles quoting and flag overrides, or use structured API request metadata. To assess configured privileges/mounts, use the runtime enrichment contract. Do not export raw command arguments into ordinary alerts.

**Acceptance criterion:** Text-search columns and alert wording explicitly describe text indicators. Parsed requests, runtime configuration, container startup and host access remain separate observations.

### QA-003 — Medium: retain configured-state terminology and unknown mount status

**Evidence of the issue:** Q-005 handles both `create` and `start` events, but its derived field is named **`HostRootMounted`**. A matching configuration on `create` does not establish that the container started or the filesystem was mounted. The prose at line 295 correctly cautions against assuming startup, so the field should reflect that boundary too.

There is also a data-quality conflict with line 253's instruction not to fabricate false values. If a row has `Privileged=true`, `Mounts` missing and `ConfigurationAvailable=false`, it survives the query, but `coalesce(RootMountCount, 0) > 0` reports **false** for root mounting. Missing mount inspection means **unknown**, not an inspected absence of a root bind. Even where no row survives, a zero-result query cannot establish absence of risky configuration.

**Suggested replacement KQL — untested, requires the existing custom-table contract:**

```kusto
// PROPOSED AND UNTESTED: configuration leads, not proven mounts/escape.
let Events = DockerEvents_CL
    | where TimeGenerated > ago(1h)
    | where EventAction in ("create", "start");
let RootMounts = Events
    | mv-expand Mount = Mounts
    | where tostring(Mount.Type) == "bind"
        and tostring(Mount.Source) == "/"
    | summarize RootMountCount = count() by EventId;
Events
| join kind=leftouter RootMounts on EventId
| extend RootMatchCount = coalesce(RootMountCount, 0)
| extend HostRootBindConfigured = case(
    RootMatchCount > 0, true,
    ConfigurationAvailable == true, false,
    bool(null))
| where Privileged == true or HostRootBindConfigured == true
| project TimeGenerated, EventId, DaemonId, ContainerId,
          EventAction, Privileged, HostRootBindConfigured,
          ConfigurationAvailable
```

This preserves a verified positive mount-config match even when other configuration is incomplete, returns false only when complete configuration establishes no matching bind, and otherwise retains null. Define `ConfigurationAvailable=true` as **complete, successfully parsed inspection of the required configuration**, with an empty `Mounts` array meaning an inspected empty list; null/missing means unknown. Keep `Privileged` null when uncollected. A separate coverage query must expose missing enrichment, malformed/non-array mounts and empty/nonunique event identifiers.

The globally unique, nonempty `EventId` contract remains essential to avoid cross-event join contamination. The left join is appropriate and preserves privileged containers with empty mount arrays. Native Docker events still require timely inspection/enrichment; these custom fields are not native event guarantees.

**Acceptance criterion:** Configuration-derived columns never imply actual mount execution; missing mount inspection remains unknown; collection-health handling is defined. Container start and host access require their own evidence.

### QA-004 — Low, optional: parameterize the hunting window

Each query uses `ago(1h)`. These are valid hunting windows, but they are not the fifteen-minute window suggested for a five-minute scheduled rule. Literal deployment would scan a wider period and repeatedly return old candidates unless deduplication is effective. The original already warns that scheduling requires adaptation, so this is not a query syntax defect.

**Suggested wording:** “The six examples use a one-hour hunting window. Replace it with the production rule's measured lookback and define source-event deduplication before scheduling.” Use a `Lookback` variable in deployment versions. Consider an explicit upper time bound and monitor future/skewed timestamps. Do not derive enterprise correlation times from screenshot filenames or unvalidated HTTP Dates.

### QA-005 — Low, optional: modernize audit watches

The `-w` templates are recognizable audit rules once placeholders resolve and the paths exist, but they are legacy/deprecated watch syntax. Add supported syscall-style directory/path rules with architecture and permission filters where suitable, using the deployed audit/kernel version. Directory watches may not cover nested mount points as operators expect; bind/container mount boundaries and inode replacement need a collection test.

The existing nonexistent-file, UID/architecture, rename/replacement and performance warnings are sound. This review does not prescribe a universal replacement rule or certify coverage of denied opens, reads/writes or container namespaces. No audit rules should be loaded on the investigated system as part of this QA.

## 2. Evidence and ATT&CK consistency

**PASS.** The seven rows at lines 15–21 match the supplied findings/register: frames 24711, 24825, 25572, 26895, 31123, 32002 and footer packet 32111. Version **2023.11.3**, build **147512**, archive/JSP names and `/tmp/Creds.txt` are consistent. The document does not substitute background frame 32010 for F-007's command reference or turn client POSTs into responses. This is a document comparison; packet/screenshot linkage was not re-audited.

| Detection | Grounding and completeness | Assessment |
|---|---|---|
| D-001 | F-002; seven required fields present | Upload is submission; archive inspection/deployment checks remain proposed |
| D-002 | F-002/F-003; seven fields | File-change monitoring is an outcome-validation opportunity, not a claim that JSP files were installed |
| D-003 | F-003–F-007; seven fields | Command parameters are requests; technique tags are command-specific rather than assigned wholesale |
| D-004 | F-005; seven fields | Actual shell spawning is explicitly unverified; fix QA-001's grouping |
| D-005 | F-004/F-005; seven fields | Read and write differ; no recovered contents, credential theft or account-password change is asserted |
| D-006 | F-006/F-007; seven fields | Client/daemon correlation is required; generic Docker events are not indiscriminately mapped |
| D-007 | F-006; seven fields | Privileged-only request is not mapped to Escape to Host |
| D-008 | F-007; seven fields | Host-root bind detection is independent of privileged mode; actual access remains unverified |
| D-009 | F-007; seven fields | Binary, syscall, root change and host escape are distinguished |
| D-010 | Preventive/control detection; seven fields | No account/token-creation event or new case technique is invented; fix QA-001's grouping |
| D-011 | F-001; seven fields | Routing/version checks retain the Low-confidence exploitation hypothesis |

The seven fields checked for each entry were objective, telemetry, proposed logic, ATT&CK relevance, false positives, investigation steps and limitations. D-001/D-002/D-003 and D-006/D-007/D-008/D-009 overlap as useful evidence stages, not duplicate incident findings. A production correlator should group their candidates by stable request/artifact/host/container identities to prevent duplicate incidents; textual/time proximity alone is insufficient.

| Technique and official name in the source mapping | Retained use/status |
|---|---|
| **T1190 — Exploit Public-Facing Application** | F-001/D-011: tentative, Low confidence; no confirmed CVE-2024-27198 exploitation |
| **T1505.003 — Server Software Component: Web Shell** | F-002/F-003 and associated detections: tentative, Moderate confidence; no proven installation/persistence |
| **T1083 — File and Directory Discovery** | F-003's `ls`: observed attempt, High confidence; no returned listing |
| **T1059.004 — Command and Scripting Interpreter: Unix Shell** | F-005's explicit `bash -c`: observed attempt, High confidence; no successful shell execution asserted |
| **T1565.001 — Data Manipulation: Stored Data Manipulation** | F-005: tentative, Moderate confidence; intended write, not proven manipulation or achieved Impact |
| **T1610 — Deploy Container** | Both Docker requests: observed attempts; F-006 High command-fit/Moderate stream confidence; F-007 Moderate overall confidence |
| **T1611 — Escape to Host** | F-007/D-008/D-009: tentative, Moderate confidence; not assigned to F-006's privileged flag alone |

No formal technique is assigned to F-004's local-file read or D-010's preventive identity control. No additional ID or upgraded successful tactic/technique was identified. The QA suggestions also preserve this seven-technique set.

## 3. KQL table assumptions and technical validity

### Table inventory

| Table/source | Where actually used | Requirement and limit |
|---|---|---|
| `DeviceProcessEvents` | Q-001 and Q-002 | Native Defender hunting schema; supported onboarded endpoints and collected process events. Not guaranteed in Sentinel without the appropriate connector/stream. |
| `DeviceFileEvents` | Q-003 | Native Defender hunting schema; OS/sensor-specific file-event coverage, not complete Linux read/write auditing. |
| `TeamCityHttp_CL` | Q-004 | Explicitly assumed custom schema; requires administrator-created table, DCR/ingestion, HTTP parsing and sanitized metadata. |
| `DockerEvents_CL` | Q-005 | Explicitly assumed custom lifecycle/configuration schema; not the raw Docker event format. |
| `TeamCityAudit_CL` | Q-006 | Explicitly assumed custom schema with version-specific audit-event normalization and an approval source. |
| `DeviceNetworkEvents` | **Not used by any query** | Could add endpoint connection context if collected; does not supply HTTP request bodies or full Docker API settings by itself. |
| `CommonSecurityLog` | **Not used by any query** | A future CEF/WAF implementation needs vendor-specific field/parser mapping; it cannot be substituted for Q-004 by changing only the table name. |
| `Syslog` | Mentioned as a collection option at line 331; **not queried** | AMA/DCR/forwarding required; raw `SyslogMessage` is not necessarily a complete reconstructed audit event. |
| `SecurityEvent` | **Not used by any query** | Windows Security telemetry requires its own event/policy/schema mapping; it is not Sysmon or a Linux process source. |
| `WindowsEvent` / `Event` | Mentioned at line 333; **not queried** | Possible Sysmon ingestion destinations depending on connector/configuration; parsing differs. |

The column spellings used for native tables are consistent with known Defender schema conventions: `Timestamp`, `DeviceId`, `DeviceName`, `ReportId`, `ActionType`, `FileName`, `AccountName`, `InitiatingProcessAccountName`, `InitiatingProcessFileName`, `ProcessCommandLine`, `FolderPath` and `SHA256` in their respective tables. Field existence in a supported schema does not establish population, sensor coverage, action-type emission or workspace availability. Verify these in the deployment tenant, especially Linux file events, hash population and process identity details.

### Q-001 — Unix shells associated with the TeamCity server (D-004)

**Original heading line 170; query lines 175–187. Static syntax assessment: plausible under the native schema. Coverage: first-pass identity-associated shell hunt, not a completed ancestry/approval detector.**

| Line(s) | Line review |
|---|---|
| 175 | Correctly labels the code untested; no effect on execution. |
| 176 | Valid dynamic host-list declaration. Replace placeholder; align full/short device names and known aliases. |
| 177 | Valid dynamic account list. Use actual service-account representation; do not assume a literal `teamcity` account. |
| 178 | Appropriate native process table, conditional on availability. |
| 179 | Valid datetime/time-span comparison using `Timestamp`; one-hour hunt, not capture time. See QA-004. |
| 180 | `in~` is case-insensitive membership; reasonable for configured host matching. |
| 181 | Valid string comparison. Confirm the source emits the selected `ProcessCreated` action. |
| 182 | Valid case-insensitive shell-name membership. Limited list; renamed binaries, other interpreters and script-only telemetry can be missed. |
| 183–184 | Valid parenthesized dynamic-list membership and Boolean `or`. Matches child or immediate-parent account, not a verified JVM ancestor; missing/empty accounts cannot match. Case-insensitive matching may merge distinct Linux account spellings. |
| 185–187 | All projected columns belong to the native process schema. Raw command arguments are not exposed. Additional process identity/creation-time fields are needed for reliable deeper ancestry joins. |

**Exact adaptations:** Configure hosts/accounts; inventory actual action types; validate lineage using available process identities and creation times; join approved job/change context; retain event identifiers for restricted command-line investigation. An account match alone can include unrelated use of the same identity. The original correctly discloses the first-pass limitation at lines 172 and 190.

### Q-002 — Docker/chroot process leads (D-006–D-009)

**Original heading line 192; query lines 197–211. Static syntax assessment: plausible; semantic correction QA-002 required.**

| Line(s) | Line review |
|---|---|
| 197 | Correct untested/text-indicator qualifier. |
| 198 | Valid dynamic client list; determine whether the client and daemon are different machines. |
| 199 | Appropriate native process table if collected. |
| 200 | Valid one-hour `Timestamp` filter; same scheduling adaptation as Q-001. |
| 201 | Valid case-insensitive device membership. |
| 202 | Valid `ActionType` filter; verify actual emitted values. |
| 203 | Valid filename membership. Includes all operations of these binaries, not just unapproved deployments. Direct API clients and renamed binaries are missed. |
| 204–205 | `matches regex`, the verbatim string, whitespace classes, noncapturing group and inline case option are consistent with KQL syntax. Bare/explicit true flag text can match; explicit `--privileged=false` alone does not. Entire-line searching cannot establish argument position or effective option semantics. |
| 206–207 | Valid regex construction for a literal root-source volume flag. Supports common `-v`/`--volume` forms; omits `--mount`, quoted paths and semantic argument parsing. Source/daemon interpretation still needs enrichment. |
| 208 | `=~` is case-insensitive equality. Identifies a literal `chroot` process filename only, not an embedded container entry command or successful root change. |
| 209–211 | Projection is schema-consistent and avoids raw command output; indicator names should be revised as in QA-002. |

**Exact adaptations:** Configure devices and workload baseline; use command-line availability/completeness status; parse actual Docker arguments/API requests when attributing requested settings; collect daemon lifecycle/configuration and `chroot` syscall/entry-command data for stronger coverage. No Unix-shell mapping should be assigned to Windows `docker.exe` merely because it controls a Linux daemon. Returning all Docker processes is acceptable for hunting, not a ready high-confidence alert.

### Q-003 — JSP/plugin file-change candidates (D-002)

**Original heading line 216; query lines 221–234. Static syntax assessment: plausible under the file schema. Coverage: file-change candidates, not content/installation verification.**

| Line(s) | Line review |
|---|---|
| 221 | Correct untested/configuration qualifier. |
| 222 | Valid host-list declaration; discover actual control-server devices. |
| 223 | Valid string declaration, explicitly placeholder path. Configure every relevant plugin/resource root; use no trailing slash for this formulation. |
| 224 | `strcat` correctly creates a directory prefix. |
| 225 | Appropriate file-event table when supported; not a universal Linux audit feed. |
| 226 | Valid `Timestamp` time filter. |
| 227 | Valid case-insensitive host membership. |
| 228 | Valid string `in` filter; verify each action type is emitted for the relevant OS/sensor. File rename/deletion and overwrite coverage varies. |
| 229 | `==` and `startswith_cs` are case-sensitive; this correctly enforces Linux directory boundaries. Windows separators/case need a separate adaptation. |
| 230–231 | `endswith` is case-insensitive; `or` joins the extension conditions correctly. Broad archive extensions include benign updates and can miss renamed/archived content. |
| 232–234 | Projected fields are schema-consistent. `SHA256` can be empty; obtain a verified hash through an appropriate collection path. |

**Exact adaptations:** Discover roots, validate file coverage/actions, correlate writer lineage and trusted hashes/content/changes, and implement an independent integrity inventory. These events cannot prove a credential read, an installed/served JSP or command execution. The original already states these limitations; no required syntax repair is identified.

### Q-004 — Uploads and JSP command submissions (D-001/D-003)

**Original heading line 255; query lines 258–270. Static syntax assessment: plausible only after implementing the declared custom schema.**

| Line(s) | Line review |
|---|---|
| 258 | Correct custom-contract/untested qualifier. |
| 259 | Custom table, not a built-in Sentinel TeamCity source. |
| 260 | Valid `TimeGenerated` comparison if source time is correctly normalized. |
| 261 | `=~` correctly matches POST case-insensitively. Other methods remain outside this example. |
| 262 | `endswith` is case-insensitive and tolerates an application context prefix. Match the normalized resource path, not a raw query-bearing URI. |
| 263–265 | Regex path test plus Boolean `and` is syntactically reasonable. Both typed bool flags must be true; absent/unknown inspection is excluded, not established clean. Body availability alone must not be equated with successful form parsing. |
| 266 | Correct union of upload and command-request candidates. It returns approved uploads too; this is disclosed. |
| 267–268 | `iif` correctly classifies matching rows; upload takes precedence if both conditions match. |
| 269–270 | Projection uses explicitly declared custom fields, with sanitized `CommandKind` rather than raw command values. |

**Exact adaptations:** Create table/DCR; implement content-type-aware URL/form/multipart parsing and error status; populate actual request/host/principal identifiers; add approval/artifact correlations and incomplete-inspection health monitoring. Derive D-011 routing features before discarding sensitive query strings. Neither the path nor the bool metadata proves installation or execution. No `parse_json` or URL decoder is implemented by this KQL itself.

### Q-005 — Effective privileged configuration or root bind mounts (D-007/D-008)

**Original heading line 275; query lines 278–292. Static syntax assessment: plausible under the custom schema; QA-003 required for semantics/unknowns.**

| Line(s) | Line review |
|---|---|
| 278 | Correct untested/enrichment qualifier. |
| 279–281 | Valid tabular `let` definition, time filter and lowercase normalized-action filter; semicolon terminates the binding. Neither action name is asserted as a raw vendor field format. |
| 282–283 | Valid second binding and `mv-expand` of a typed dynamic array. Empty arrays produce no right-side mount rows; null/malformed input requires coverage handling. |
| 284–285 | `tostring` and property access are appropriate for dynamic mount objects. Missing values become empty strings and cannot positively match; literal lowercase `bind` and source `/` require the stated normalization. |
| 286 | Valid `summarize count()` by `EventId`, producing one root-match count per identifier. Global uniqueness/nonemptiness is a critical ingestion requirement. |
| 287–288 | Valid `leftouter` join; correctly preserves privileged source events with no root matches. Duplicate source rows or identifier collisions can cause duplicate/cross-event attribution. |
| 289 | Numeric `coalesce` and comparison are syntactically plausible, but count absence does not distinguish inspected no-bind from missing inspection. Field name also overstates actual mount state. See QA-003. |
| 290 | Valid Boolean risk filter. Null privileges cannot provide a positive privilege match; missing-data cases need a separate health path. |
| 291–292 | Projected fields are in the custom contract/derived schema. Rename the mount field and preserve nulls as suggested. |

**Exact adaptations:** Build continuous event collection plus timely inspected config; define complete-vs-partial status and mount object types; enforce stable nonempty event IDs; monitor failed enrichment, duplicate/replayed events and container removal races; compare policy approvals. The query does not contain image/entry-command, runtime namespace or actual file-access information. `--mount`, resolved aliases and nonliteral/root-exposing volume mechanisms need additional normalized metadata if coverage is expanded. A start event can establish that container's lifecycle transition, not host compromise.

### Q-006 — Unapproved or approval-unknown identity changes (D-010)

**Original heading line 297; query lines 300–308. Static syntax assessment: plausible under the custom schema; null handling is deliberate and correct.**

| Line(s) | Line review |
|---|---|
| 300 | Correct untested/normalized-name qualifier. |
| 301 | Explicitly assumed custom audit table. |
| 302 | Valid source-time filter if normalized correctly. |
| 303 | Valid case-sensitive `in` filter for the lowercase contract actions, not literal vendor event strings. |
| 304 | `coalesce(ChangeApproved, false) == false` includes false and null approval states and excludes true. This is appropriate for candidate generation, not proof of unauthorized activity. |
| 305–306 | `isnull` and `iif` preserve the distinction between unknown and known-not-approved status in the output. |
| 307–308 | Declared custom fields are projected; opaque token record ID is used instead of a usable token. `OperationResult` is retained. |

**Exact adaptations:** Discover supported TeamCity events/results; create schema/parser and approval join; reconcile inventories; ensure unknown approvals remain null rather than fabricated false. The query does not implement D-010's separate “unexpected actor/context despite approval” branch, so it covers a disclosed subset, not the whole control. Add that branch only with a defined baseline/enrichment. Failed events remain attempts and must not be reported as created accounts/tokens. This is preventive monitoring, not case evidence.

## 4. Collection realism and incident response

### Linux, TeamCity, Windows and Docker collection

- **Linux auditd (lines 315–331):** Templates are non-runnable until UID/path/architecture placeholders are resolved. `execve`/`execveat` and `chroot` syscall collection is technically plausible where supported. Reconstruct related records by full event identity and retain host/boot context. Unset daemon login IDs, effective-UID transitions, nonexistent paths, mounts/inode replacement and event loss are correctly noted. Not every syscall emits every named companion record; never require `PATH`/`CWD`/`EXECVE` universally. Read-intent opens, successful reads/writes and data returned to a remote requester are different facts. QA-005 is an optional modernization.
- **TeamCity logging (lines 42, 62, 132, 162, 245–251):** Version-specific administrative export, application logs and inventory comparison are reasonable. Ordinary access logs do not generally supply form-body `cmd` parameters or token-creation evidence. No unsupported specific log filename/event name is asserted. Custom body/audit parsers remain administrator-enabled dependencies; test coverage/results before use.
- **Sysmon (lines 160, 333):** Process creation, file creation, configured network/deletion events are correctly scoped to Windows-side infrastructure. Sysmon Event 11 is not complete write/read auditing, and Sysmon does not expose remote Linux mount/syscall activity. Table/channel collection and parsing need configuration; the document does not invent an existing Windows host.
- **Docker (lines 161, 247, 253, 335):** Continuous lifecycle forwarding, timely configuration enrichment and `--rm` race handling are realistic. Raw event `Type`/`Action`/container actor metadata is not the same as inspected mount objects or `HostConfig.Privileged`. Default service logs/events do not guarantee authenticated operator, complete history, image digest, entry command or secrets-safe inspect output. Event ID and configuration-status contracts must be implemented; correct QA-003. Application stdout is not a control-plane audit log and requires attribution.

### Seven-stage response review

| Original stage and lines | Assessment |
|---|---|
| **“4.1 Initial triage”**, 351–357 | PASS: checks source/parser health, request-versus-result, approvals and response linkage; maintains priority/severity distinction. |
| **“4.2 Scope identification”**, 359–365 | PASS: inventories server/agents/daemon, namespaces, identities and reachable dependencies; separates confirmed from possible scope. |
| **“4.3 Evidence preservation”**, 367–373 | PASS: preserves capture/log/artifact/volatile context, hashes/provenance, restricted secrets and read/write chronology; avoids representing newly enabled collection as historical evidence. |
| **“4.4 Containment”**, 375–381 | PASS: allows risk-based targeted containment, considers build disruption and token scope, and records lost volatile evidence/rollback conditions. Line 349 correctly permits urgent containment alongside preservation. |
| **“4.5 Eradication”**, 383–389 | PASS: repairs verified access paths and artifacts; rebuilds when privileged compromise or lost trust warrants it; does not assume JSP removal alone restores CI trust. |
| **“4.6 Recovery”**, 391–397 | PASS: staged functional/control validation, trusted baselines, service-owner acceptance, sensor health and rollback. |
| **“4.7 Post-incident monitoring”**, 399–405 | PASS: recurrence/alternative-path monitoring, coverage metrics, narrow allowlists and evidence-based severity reassessment. |

Credential rotation is appropriately based on implicated/exposed secrets and access scope, not the filename or supplied credential-labelled text. Proposals should allow risk-based rotation when corroborated compromise creates credible secret exposure even without direct exfiltration proof. No step claims these actions happened in the lab. There is no required playbook sequencing correction.

The control ranking at lines 409–422 is practical: patch state, plugin/identity integrity, least privilege, Docker access/privilege/mount policy and telemetry are prioritized. Many actions share P1; assigning owners/order/dependencies would improve implementation planning but is optional. Current-release remediation is not confused with a historical minimum fixed version.

## 5. Checklist before integration

### Required document/logic corrections

- [ ] **QA-001:** Parenthesize D-004 and D-010 so event-type and approval/context guards apply to every intended branch; retain attempts versus confirmed audit changes.
- [ ] **QA-002:** Rename Q-002's privilege flag result and clarify that regex matches are text indicators; require semantic parsing/runtime enrichment before claiming requested/configured privileges.
- [ ] **QA-003:** Rename Q-005's mount field to configuration terminology, preserve unknown inspection status, and define complete/partial configuration semantics.
- [ ] Preserve the seven findings/techniques, tentative statuses, secret-safe projections, preventive-only identity control and undetermined incident severity while making those corrections.

### Operational prerequisites — already disclosed, not new incident findings

- [ ] Confirm native tables/columns/action types and actual OS-specific data coverage in the intended Defender/Sentinel environment; do not substitute `Syslog`, `CommonSecurityLog` or `SecurityEvent` without a separate parser/schema design.
- [ ] Create and verify custom DCR/table contracts, body parsing/error status, audit result normalization, approval source, event-ID uniqueness and timely Docker configuration enrichment.
- [ ] Discover actual host/account/path/daemon inventories; validate deeper process ancestry, source clocks and server-versus-agent workload baselines.
- [ ] Define collection-health alerts, retention, missing/partial-data treatment, scheduling/deduplication and response ownership.
- [ ] Compile and validate adopted queries with controlled synthetic/benign fixtures in the target platform before deployment; keep all examples labelled untested until results are recorded. **Do not rerun the case PCAP/screenshot investigation to satisfy this QA.**

These prerequisites gate operational deployment; they are not assertions that the lab had those telemetry sources or that detection effectiveness is established.

## 6. Optional improvements

- **QA-004 (Low):** Parameterize the one-hour hunt windows, document scheduling lookback/upper bounds and source-event deduplication (query time lines listed above; section 3.5, line 341).
- **QA-005 (Low):** Add supported modern audit path/directory rule alternatives and explicit mount-boundary coverage tests (section 3.4, lines 315–329).
- **Q-001, lines 183–190:** Add validated process identity/creation-time fields for ancestry and domain/UID-aware account normalization. Avoid expanding this into an unsupported claim that an account match proves JVM parentage.
- **Q-006/D-010, lines 133, 246, 303–311:** Define an approved-but-unexpected-actor branch and normalized successful/failed change classification if implementing the full control.
- **D-006–D-009/Q-005, lines 93–127, 247–295:** Add entry-command, image, daemon namespace and path-resolution metadata for deeper container attribution. Broaden beyond literal bind source `/` only with a documented rule scope and supported telemetry.
- **D-001–D-003 and D-006–D-009, lines 39–127:** Define grouping/escalation across request, artifact, process and runtime candidates to reduce duplicate incidents; retain their distinct evidence meanings.
- **Section 5, lines 409–422:** Assign owners, change dependencies, implementation sequence and measurable coverage goals to the numerous P1 controls.

## Final disposition

**PASS WITH CORRECTIONS.** Evidence accuracy, ATT&CK consistency, collection boundaries and incident-response sequencing pass the static review. Apply QA-001–QA-003 before integrating the logic; fulfil the disclosed collection/schema/testing prerequisites before operational deployment. No successful incident outcome or conclusive incident-severity rating is established.

Only this requested QA document was created after review. The original detection/response document and source-of-truth documents were not modified; their content hashes were compared with the read-only review baseline. No PCAP or screenshot audit was rerun, no rules deployed, and nothing was published, committed or uploaded.
