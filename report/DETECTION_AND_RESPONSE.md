# JetBrains TeamCity — Detection Engineering and Incident Response

Prepared: **2026-11-07**. Context: **CyberDefenders JetBrains investigation**.

**All detection logic, pseudocode, KQL and collection templates below are proposed and untested.** They were not executed against the PCAP, an endpoint, a SIEM workspace or a Docker daemon. No enterprise telemetry, alert, response action or successful incident outcome is asserted. Implementation requires local schema validation, collection configuration and controlled testing.

The investigation examined network traffic displayed in preserved screenshots. **Incident severity remains undetermined.** High response priority for the upload and Docker requests reflects potentially serious requested capabilities, not confirmed exploitation, installation, execution, credential theft, container deployment or host compromise.

Sources: [executive summary](EXECUTIVE_SUMMARY.md), [technical findings](TECHNICAL_FINDINGS.md), [evidence register](../evidence/TECHNICAL_EVIDENCE_REGISTER.md), [timeline](../evidence/ATTACK_TIMELINE.md) and [latest ATT&CK mapping](../evidence/MITRE_ATTACK_MAPPING.md).

## 1. Investigation basis and detection scope

| Finding | Observed evidence and selected packet | Existing response priority | ATT&CK assessment retained |
|---|---|---|---|
| **F-001** | EV-008 / 24711: advertised TeamCity **2023.11.3, build 147512**, with unusual routing visible in stream context | Medium | **T1190 — Exploit Public-Facing Application:** tentative, Low confidence; CVE-2024-27198 remains a hypothesis |
| **F-002** | EV-014 / 24825: plugin upload naming `NSt8bHTg.zip`, with command-handling JSP content | High | **T1505.003 — Server Software Component: Web Shell:** tentative, Moderate confidence |
| **F-003** | EV-060/EV-061/EV-062 / 25572: POST to `/plugins/NSt8bHTg/NSt8bHTg.jsp` with `cmd=ls` | Medium | **T1083 — File and Directory Discovery:** observed attempt, High confidence; **T1505.003:** tentative, Moderate confidence |
| **F-004** | EV-065 / 26895: submitted `cat /tmp/Creds.txt` | Medium | No technique assigned to the local-file read; file contents and credential disclosure are unverified |
| **F-005** | EV-066 / 31123: explicit `bash -c` requesting credential-labelled text be redirected to `/tmp/Creds.txt`; values remain redacted | Medium | **T1059.004 — Command and Scripting Interpreter: Unix Shell:** observed attempt, High confidence; **T1565.001 — Data Manipulation: Stored Data Manipulation:** tentative, Moderate confidence |
| **F-006** | EV-068/EV-069 / 32002: submitted `docker run --rm -it --privileged ubuntu`; no root bind mount or `chroot` | High | **T1610 — Deploy Container:** observed attempt; High command-fit confidence, Moderate stream association |
| **F-007** | EV-070 / footer packet 32111: submitted `docker run --rm -it -v /:/host ubuntu chroot /host`; no `--privileged` flag | High | **T1610:** observed attempt; **T1611 — Escape to Host:** tentative; Moderate overall confidence |

These are the same **seven mapped techniques**; no technique is added or removed. Proposed broader monitoring does not create new case findings. In particular, **administrative account or token creation is not established by these seven findings** and is covered below as an enterprise preventive control with no additional technique assignment.

The selected order is **24711 → 24825 → 25572 → 26895 → 31123 → 32002 → 32111**. F-004's read cannot verify F-005's later write. Frames 31124 and 32003 are client POSTs; nearby HTTP 200 rows 32008/32010 are not execution proof. F-007's frame/body association uses the stream footer, not the background selection of 32010. Absolute timing and several stream associations remain unresolved.

### Common implementation requirements

- Discover the actual TeamCity **server and agent** hosts, service identities, plugin/data/webroot paths, reverse proxies and Docker daemon locations. Shells and Docker use may be normal on agents; do not apply an agent baseline to the control server.
- Parse HTTP methods, paths, content types and form parameters after appropriate URL/form decoding. Preserve the original request separately under restricted access; do not repeatedly decode arbitrary text until a desired match appears. Account for context paths, multipart content, parameter truncation and parser errors.
- Keep passwords, Bearer tokens, cookies, CSRF values, token-bearing query strings and credential-bearing command arguments out of ordinary SIEM projections and alert descriptions. Export command categories, parameter-presence flags and opaque identifiers. Restricted raw evidence may still be needed for investigations.
- Correlate request IDs, host identity, process ancestry and container IDs. Source IP and temporal proximity alone do not prove causality. Check clock offsets, NAT/proxy routing and packet duplication before aggregating counts.
- Maintain approved plugin hashes, administrative changes, build jobs, service-account activities and container policies. Treat missing approval evidence as **unknown**, not automatically malicious. Allowlist narrowly by identity, artifact and approved workload; expire exceptions.

## 2. Detection engineering catalog

Every rule below is **proposed and untested**. “Investigation steps” describe what an analyst should do after a future alert; none were performed as enterprise response actions during this lab. A rule match is a lead whose confidence and outcome must be evaluated separately.

### D-001 — Suspicious TeamCity plugin uploads

- **Detection objective:** Identify unapproved uploads and archives carrying executable command-handling resources. Basis: F-002.
- **Relevant telemetry source:** TeamCity audit/application logs, HTTP gateway/WAF metadata, controlled upload inspection and plugin inventory. Upload payload inspection and hash extraction require configuration; ordinary access logs may show only method/path/status.
- **Proposed logic / pseudocode:** `IF TeamCity request is POST to pluginUpload.html THEN record uploader/request/artifact identifiers; flag unknown approval or unapproved artifact hash; raise priority if isolated archive inspection finds unexpected JSP resources with command-input and process-launch constructs.` Also monitor alternate upload routes discovered for the deployed version. The case archive name is a search aid, not a universal signature.
- **Relevant ATT&CK technique:** T1505.003, preserving the tentative placement interpretation; upload alone does not demonstrate persistence.
- **Expected false positives:** Approved plugin upgrades, custom diagnostics and authorized security testing.
- **Investigation steps:** Validate the operator and change record; recover the paired response and archive; inspect a copy in isolation; compare installed artifacts/inventory and later endpoint requests.
- **Limitations:** ZIP content may be compressed, truncated or unavailable. A suspicious code fragment is not a complete code review. Submission, storage, installation and activation require separate evidence.

### D-002 — Unexpected JSP files or webshell-like components

- **Detection objective:** Find new or changed executable resources outside the approved deployment baseline. Basis: F-002/F-003.
- **Relevant telemetry source:** File-integrity monitoring, supported endpoint file events, Linux audit watches, deployment records and plugin/JAR inventories. Discover and monitor actual expanded-resource locations as well as archives.
- **Proposed logic / pseudocode:** `IF create/modify/rename in protected TeamCity resources affects JSP/JAR/plugin archive AND artifact is not an approved baseline/change THEN investigate; increase confidence when isolated content analysis links request parameters to process execution.` Match `request.getParameter("cmd")` as a case clue, not sufficient proof of a webshell.
- **Relevant ATT&CK technique:** T1505.003, tentative in the investigation.
- **Expected false positives:** Plugin installation, application upgrades, generated resources and maintenance.
- **Investigation steps:** Collect hashes, ownership, timestamps, writer process and deployment provenance; compare with trusted packages; establish whether the file was served or invoked.
- **Limitations:** Not all endpoint products report every modification. Archived JSPs and ephemeral expanded files may evade extension-only rules; malicious code can use other parameter names or launch methods. File presence does not establish activation or execution.

### D-003 — HTTP POSTs to JSP endpoints carrying command parameters

- **Detection objective:** Detect attempted use of an unapproved server-side command interface. Basis: F-003 through F-007.
- **Relevant telemetry source:** Reverse proxy/WAF with parsed body metadata, application request instrumentation or authorized HTTP inspection. TLS termination/body inspection and secret-safe parsing may need additional configuration.
- **Proposed logic / pseudocode:** `IF POST to a TeamCity JSP resource AND parsed form has cmd parameter THEN create request-level lead; categorize command as discovery, read, write, Docker, chroot or other; correlate with approved endpoint inventory and host process events.` A decoded `ls` specifically requests directory discovery. Retain a separate lower-context path-only hunt when bodies are unavailable.
- **Relevant ATT&CK technique:** T1505.003 tentative; T1083 for the `ls` attempt. Use T1059.004 only for an explicit Unix interpreter, T1565.001 tentatively for the write, and T1610/T1611 with the Docker distinctions below. Do not assign all techniques to every `cmd` request.
- **Expected false positives:** Authorized diagnostic pages, penetration tests and rejected probes.
- **Investigation steps:** Validate the parser and full request; identify principal and origin; pair the actual response; correlate with endpoint lineage and deployment artifacts.
- **Limitations:** Access logs usually omit form bodies. A 200 status, command parameter or matching URI does not prove a functioning JSP or executed command. Other methods, encodings and parameters require broader coverage.

### D-004 — Shell processes associated with TeamCity

- **Detection objective:** Identify unexpected Unix shell starts associated with the TeamCity service identity or verified server process lineage. Basis: F-005's submitted `bash -c`; actual process spawning is unverified in the case.
- **Relevant telemetry source:** Linux EDR process events or auditd execution records; service configuration and build-job metadata. Windows process telemetry is complementary only for actual Windows infrastructure.
- **Proposed logic / pseudocode:** `IF (IsUnixShellProcessStart AND (TeamCityServiceIdentityMatch OR VerifiedTeamCityAncestor) AND (ApprovalState IN ("Unknown", "NotApproved"))) THEN create a shell-activity investigation candidate; prioritize a control-server shell after a suspicious JSP request.` Both identity branches require a Unix shell process-start event and an approval state of Unknown or NotApproved. Derive approval state from maintained workload/change records; unknown approval is an investigation lead, not proof of unauthorized execution. Walk ancestry beyond the immediate parent and check process creation times to avoid PID-reuse errors.
- **Relevant ATT&CK technique:** T1059.004 for explicit Unix shell activity. The case's Windows infrastructure, if any, is unknown; Windows shell events must not be relabelled Unix Shell solely to fit this mapping.
- **Expected false positives:** Build runners, maintenance scripts, deployment hooks and approved diagnostics.
- **Investigation steps:** Recover the parent/child tree, executable path/hash, effective user, working directory, container context and job ID; correlate command output, file access and exit evidence.
- **Limitations:** Daemon accounts may have unset audit login IDs; account-only rules can miss privilege changes. A process start supports interpreter launch, not successful completion of each shell command. `echo` may be a shell builtin with no separate process.

### D-005 — Commands and file operations involving `/tmp/Creds.txt`

- **Detection objective:** Identify requested or actual access to the case path, keeping reads and writes distinct. Basis: F-004/F-005.
- **Relevant telemetry source:** Secret-safe HTTP command categories, EDR process/file events and auditd open/write/path records. Successful reads need read telemetry, which file-creation events do not provide.
- **Proposed logic / pseudocode:** `IF command or resolved file-operation path equals /tmp/Creds.txt THEN record operation type and result; distinguish cat/read from bash plus redirection/create/truncate; correlate to the service lineage and a specific request.` Separately watch relevant temporary-file patterns after baselining; the exact case filename is not comprehensive coverage.
- **Relevant ATT&CK technique:** No assignment for the read alone. T1059.004 for explicit `bash -c`; T1565.001 remains a tentative intended-manipulation interpretation for the write. Do not infer a credential-access technique from the name.
- **Expected false positives:** Test fixtures, authorized troubleshooting and ordinary temporary-file handling.
- **Investigation steps:** Establish existence, namespace, owner, permissions and operational use; preserve restricted contents and before/after metadata if available; check denied versus successful opens/writes and subsequent readback.
- **Limitations:** Argument text does not prove a file open. A successful open does not prove contents were returned to the requester. Container paths may reference a different filesystem; replacement/rename can affect inode-watch coverage. Writing text is not an account-password change.

### D-006 — Unexpected Docker CLI or daemon activity

- **Detection objective:** Detect Docker control activity outside approved CI workloads and correlate clients with daemon actions. Basis: F-006/F-007.
- **Relevant telemetry source:** Client-side EDR/auditd, Docker daemon service logs, continuously collected lifecycle events, authenticated API audit metadata where implemented, and job records.
- **Proposed logic / pseudocode:** `IF docker client starts under TeamCity lineage outside approved jobs OR daemon create/start/exec activity lacks expected workload provenance THEN investigate; link client, daemon and container identity before assigning an outcome.` Also cover direct API clients, which may use no Docker binary.
- **Relevant ATT&CK technique:** T1610 for attempted deployment. Do not map every benign Docker operation or generic daemon event to deployment; T1611 applies only to the separate qualified host-access interpretation.
- **Expected false positives:** Container build/test jobs, image pulls, routine orchestration and administration.
- **Investigation steps:** Validate command/API operation, identity, daemon endpoint, policy result and container ID; compare create/start events and effective configuration with the job record.
- **Limitations:** Local CLI telemetry may address a remote daemon. CLI start, image pull or API request does not prove container startup. Default daemon logs/events may not identify the authenticated actor or retain a complete history.

### D-007 — Privileged container requests or effective configuration

- **Detection objective:** Identify requested or granted privileged mode on CI-associated Docker hosts. Basis: F-006.
- **Relevant telemetry source:** Command arguments, API/policy request records and runtime configuration enrichment after create/start.
- **Proposed logic / pseudocode:** `Flag docker run/create with parsed privileged=true; independently flag effective HostConfig.Privileged=true on unapproved containers.` Handle bare `--privileged` and `--privileged=true`, excluding explicit false; prefer structured configuration over substring matching.
- **Relevant ATT&CK technique:** T1610 for this deployment request; do not assign T1611 to privileged mode alone.
- **Expected false positives:** Approved specialized builders, low-level test environments and administrative troubleshooting.
- **Investigation steps:** Collect container lifecycle, effective privileges/capabilities, devices, security options, daemon identity and workload approval; determine whether startup occurred.
- **Limitations:** A flag does not prove grant/startup or escape. Configuration collection can race container removal. Rootless and policy-constrained environments alter effective risk.

### D-008 — Bind mounts exposing the Docker host's root

- **Detection objective:** Detect root bind-mount requests and effective mounts, whether or not privileged mode is requested. Basis: F-007.
- **Relevant telemetry source:** Docker API create configuration, policy checks, runtime/inspect metadata and CLI arguments as a weaker fallback.
- **Proposed logic / pseudocode:** `IF normalized bind mount source is / on the daemon host THEN flag; record destination and read/write setting; correlate with container lifecycle and entry command.` Parse both volume flags and `--mount`, including option order, quotes and supported source aliases. Assess resolved paths/daemon context rather than assuming every text `/` refers to the client host.
- **Relevant ATT&CK technique:** T1610 for deployment; T1611 tentative where containment context supports an attempted host-access interpretation.
- **Expected false positives:** Approved backup, recovery, host-inspection and administrative workloads.
- **Investigation steps:** Validate source/destination/type and effective permissions on the daemon host; collect container namespaces and host-specific access records; determine whether a boundary was crossed.
- **Limitations:** Ordinary lifecycle logs do not carry full mount configuration. Symlinks/alternate sources and nested daemons complicate interpretation. A mount request or even a mounted tree is not proof of host reads, modifications or complete escape.

### D-009 — Unexpected `chroot` requests or system calls

- **Detection objective:** Detect attempts to change a process root associated with the CI service or a root-mounted container. Basis: F-007.
- **Relevant telemetry source:** EDR process records, container entry/exec configuration, auditd `chroot` syscall records or equivalent runtime instrumentation.
- **Proposed logic / pseudocode:** `IF chroot binary starts under suspicious CI/container lineage OR chroot syscall targets an unexpected root THEN investigate; prioritize correlation with D-008.` Monitoring the syscall also covers programs invoking it without a `chroot` binary.
- **Relevant ATT&CK technique:** T1611 tentative only in the host-access context; T1610 applies to F-007's enclosing deployment request. An ordinary `chroot` alone is not automatically Escape to Host.
- **Expected false positives:** Package builders, rescue environments, installers and approved filesystem isolation.
- **Investigation steps:** Collect target root, parent identity, syscall success/return code, mounts and namespaces; compare actual root change with evidence of host access.
- **Limitations:** Process arguments do not prove a successful syscall. A successful `chroot` does not join all host namespaces or prove privilege escalation. Host-wide syscall collection needs tuning and container context.

### D-010 — Suspicious administrative account, role or token creation

- **Detection objective:** Detect identity-change events with unapproved/unknown approval or unexpected actor/context that could enable later administrative activity. **Preventive control: no such event is established in F-001–F-007.**
- **Relevant telemetry source:** TeamCity audit view/export, identity/role/token inventories and version-supported application/security logs; identity-provider logs can add login context but do not necessarily record TeamCity-local token creation.
- **Proposed logic / pseudocode:** `IF ((NormalizedAction IN ("user_created", "admin_role_granted", "token_created")) AND ((ApprovalState IN ("Unknown", "NotApproved")) OR (UnexpectedActorContext == true))) THEN create an identity-change investigation candidate, retaining OperationResult as success, failure or unknown.` Both approval and actor-context branches require a normalized identity-change event. Unknown approval is an investigation lead; an approved change may also merit investigation when a defined actor/context baseline flags a deviation. Normalize actual version-specific events and compare inventories when audit coverage is incomplete; failed attempts must remain distinct from server-confirmed changes. Correlate subsequent administrative requests using opaque token-record IDs, never token values.
- **Relevant ATT&CK technique:** **No additional technique assigned.** Possible sequence correlation with the tentative T1190/T1505.003 context does not classify account/token creation under those techniques or establish a new case event.
- **Expected false positives:** Onboarding, service integrations, access reviews, token rotation and emergency administration.
- **Investigation steps:** Validate actor, operation result, target identity, role/token scope, approval, expiry and subsequent use; check that inventory changes agree with server audit records.
- **Limitations:** Audit availability/coverage varies by version and configuration. REST status alone does not prove creation; tokens may be opaque and values should not be logged. Inventory differences do not supply exact creation time or attribution.

### D-011 — Suspicious TeamCity routing and version-information access

- **Detection objective:** Identify unusual routing around server-information resources and prioritize patch-state validation. Basis: F-001.
- **Relevant telemetry source:** HTTP access/WAF metadata with restricted raw URI handling, TeamCity authentication/audit context and software inventory.
- **Proposed logic / pseudocode:** `IF TeamCity request uses unusual jsp routing to REST resources, including the case pattern /hax?jsp=/app/rest/server;.jsp, THEN investigate authorization and paired response; compare advertised version with installed release/mitigations.` Use parser-based routing features, not version alone as an exploit signature.
- **Relevant ATT&CK technique:** T1190 tentative, Low confidence in this case. Version disclosure does not establish exploitation or public exposure controls.
- **Expected false positives:** Authorized API queries, diagnostic routing, vulnerability tests and benign probes.
- **Investigation steps:** Recover full request/response linkage, principal, external reachability and mitigation records; seek exploit-specific server effects before attributing CVE-2024-27198.
- **Limitations:** Banners may differ from effective patched state. Generic `jsp=` matches are noisy; request pairing and authorization cannot be inferred from the displayed version response alone.

## 3. SIEM implementation and collection plan

### 3.1 What is directly applicable, and what needs configuration

**None of the following enterprise sources was supplied as collected telemetry in this lab.** “Directly applicable” describes how a real, already-enabled source could support a rule; it does not assert that the source exists in the investigated environment.

| Platform/source | Directly applicable when already collected | Additional configuration and boundaries |
|---|---|---|
| **Microsoft Defender XDR / Defender for Endpoint** | `DeviceProcessEvents` for process starts/ancestry; `DeviceFileEvents` for supported file activity on onboarded devices | Supported Linux/Windows onboarding, healthy EDR, appropriate licensing/retention and validated event coverage are prerequisites. Linux file-event coverage is not equivalent to complete auditd read/write auditing. No default HTTP form-body or full Docker-config visibility is implied. |
| **Microsoft Sentinel** | Existing endpoint connector data and collected TeamCity/proxy/syslog records can be queried and correlated | Select ingestion tables via supported connectors/DCRs, define parsers, verify latency and deploy analytics rules separately. Defender hunting tables are not automatically present in every Sentinel workspace. A query returning zero rows may reflect missing ingestion. |
| **Linux auditd/process telemetry** | Execution, syscall results and configured watched-path records support D-002/D-004/D-005/D-009 | Add scoped rules, collect to a durable destination, parse multiline records and monitor backlog/loss. Include daemon identities; filtering only interactive login IDs can exclude TeamCity. Auditd data does not become `DeviceProcessEvents` merely by forwarding it. |
| **Sysmon on relevant Windows infrastructure** | Event 1 process creation; Event 11 file creation; enabled Event 3 network connections and 23/26 deletion events can add context | Install/configure Sysmon and its channel collection. Event 3 requires enabling; Event 11 is not all file writes/reads. Sysmon cannot observe remote Linux processes/mounts and network events do not decode HTTP bodies or Docker API configuration. |
| **Docker daemon/container runtime** | Service logs can show daemon errors; lifecycle events can establish create/start/die/destroy for identified containers | Continuously collect events and enrich with effective container configuration before removal; retain remotely. Configure actor/API auditing or policy telemetry where available. Application stdout logs alone are not control-plane audit logs. |
| **TeamCity audit/application and HTTP logs** | Supported administrative events, application outcomes and request metadata support D-001/D-010/D-011 | Verify deployed-version coverage, export mechanisms and retention. Add sanitized form/multipart features for D-003; ordinary access logs and identity-provider sign-ins do not establish local token creation or command execution. |

Discover schema and event coverage in the target platform before adapting these examples. In Defender advanced hunting the event time is **`Timestamp`**; native Sentinel log tables generally use **`TimeGenerated`**. When Defender hunting data is ingested into Sentinel, confirm its retained fields/time semantics rather than renaming columns by assumption.

### 3.2 Native Defender KQL examples — untested

These are **untested hunting candidates**, not deployed analytics rules. They use the documented `DeviceProcessEvents`/`DeviceFileEvents` fields listed in the queries. Replace example host/account/path lists with discovered values and confirm the fields are populated for the relevant OS. For privacy, the output projects event identifiers and derived flags, not raw command lines; authorized analysts can use those identifiers to review restricted underlying records.

#### Q-001 — Unix shells associated with the TeamCity server (D-004)

Assumes onboarded TeamCity control-server devices and collected process starts. Account names are local configuration placeholders, not case evidence. Immediate account/parent filtering is a first-pass hunt, not a complete ancestry traversal.

```kusto
// PROPOSED AND UNTESTED. Replace configuration values before use.
let TcHosts = dynamic(["replace_with_teamcity_server_hostname"]);
let TcAccounts = dynamic(["replace_with_teamcity_service_account"]);
DeviceProcessEvents
| where Timestamp > ago(1h)
| where DeviceName in~ (TcHosts)
| where ActionType == "ProcessCreated"
| where FileName in~ ("bash", "sh", "dash", "zsh", "ksh")
| where AccountName in~ (TcAccounts)
    or InitiatingProcessAccountName in~ (TcAccounts)
| project Timestamp, DeviceId, DeviceName, ReportId,
          FileName, AccountName, InitiatingProcessFileName,
          InitiatingProcessAccountName
```

Extend this with reliable ancestry/job joins after validating process identity and creation-time fields. Sudo/root transitions, intermediate wrappers and service identity aliases can defeat account-only filtering. A Unix shell started for an approved agent build is not equivalent to a suspicious control-server shell.

#### Q-002 — Docker/chroot process leads (D-006–D-009)

Assumes collected process events on the configured clients. The regexes search command-line text; they do not parse Docker option positions or effective settings. They can match arguments to the container's command and miss quoted arguments, `--mount`, wrappers or direct API calls. Q-005 uses separately collected lifecycle and inspected-configuration records. A submitted command, a Docker client process start, a daemon create/start event and inspected runtime configuration are distinct observations; none alone establishes host access.

```kusto
// PROPOSED AND UNTESTED. Matches are command-line text indicators only.
let CiClients = dynamic(["replace_with_ci_client_hostname"]);
DeviceProcessEvents
| where Timestamp > ago(1h)
| where DeviceName in~ (CiClients)
| where ActionType == "ProcessCreated"
| where FileName in~ ("docker", "docker.exe", "chroot")
| extend CommandLineAvailable = isnotempty(ProcessCommandLine)
| extend PrivilegedFlagTextPresent = iif(CommandLineAvailable,
    ProcessCommandLine matches regex @"(?i)(^|\s)--privileged(?:=true)?(\s|$)",
    bool(null))
| extend RootBindFlagTextPresent = iif(CommandLineAvailable,
    ProcessCommandLine matches regex @"(?i)(^|\s)(-v\s*|--volume(?:=|\s+))/:/",
    bool(null))
| extend ChrootProcessNameMatch = FileName =~ "chroot"
| project Timestamp, DeviceId, DeviceName, ReportId,
          FileName, AccountName, InitiatingProcessFileName,
          CommandLineAvailable, PrivilegedFlagTextPresent,
          RootBindFlagTextPresent, ChrootProcessNameMatch
```

This also returns ordinary Docker processes for workload validation. A true flag-text indicator is a search lead, not proof that Docker accepted an option, created a container or exposed the host. `CommandLineAvailable` means nonempty, not complete; missing command lines produce null indicators, and false means only that the available text did not match. Use an argument-aware parser handling image/entry-command boundaries, quoting and overrides, or structured API metadata, before classifying a requested option. Use daemon lifecycle events and time-linked configuration inspection to assess creation, startup and settings. `ChrootProcessNameMatch` identifies a literal process filename; it does not detect an embedded entry-command argument or prove a successful syscall. Windows `docker.exe` may control a Linux daemon elsewhere. It is not evidence that the investigated server ran Windows, or a basis to change the case's technique mapping.

#### Q-003 — JSP/plugin file-change candidates (D-002)

Assumes supported file-event coverage and actual monitored server resource paths. The example path is a placeholder. A separate integrity inventory is needed for missed writes, archived resources and trusted-hash comparison.

```kusto
// PROPOSED AND UNTESTED. Replace host/path configuration.
let TcHosts = dynamic(["replace_with_teamcity_server_hostname"]);
let ProtectedRoot = "/replace/with/discovered/teamcity/resource/root";
let ProtectedPrefix = strcat(ProtectedRoot, "/");
DeviceFileEvents
| where Timestamp > ago(1h)
| where DeviceName in~ (TcHosts)
| where ActionType in ("FileCreated", "FileModified", "FileRenamed")
| where FolderPath == ProtectedRoot or FolderPath startswith_cs ProtectedPrefix
| where FileName endswith ".jsp"
    or FileName endswith ".jar" or FileName endswith ".zip"
| project Timestamp, DeviceId, DeviceName, ReportId,
          ActionType, FolderPath, FileName, SHA256,
          InitiatingProcessFileName, InitiatingProcessAccountName
```

`SHA256` may be empty even where the column exists; enrich with safely collected artifact hashes. This sample uses a Linux root without a trailing slash and matches directory boundaries; adapt separators and case rules for Windows paths. This is a candidate hunt, not proof of malicious content or a comprehensive filesystem monitor.

### 3.3 Sentinel normalized custom tables — explicit assumptions

The following tables **do not come from the lab and are not built-in TeamCity/Docker schemas**. They are proposed DCR-managed custom tables. Create them, supply compatible types and document parsers before using the KQL. Fields and normalized event names below are design choices, not claims about vendor log formats.

| Proposed table | Required schema for these examples |
|---|---|
| **`TeamCityHttp_CL`** | `TimeGenerated:datetime`, `TeamCityHost:string`, `Method:string`, `UriPath:string`, `RequestId:string`, `SourceIp:string`, `ActorId:string`, `BodyInspectionAvailable:bool`, `HasCmdParameter:bool`, `CommandKind:string` |
| **`TeamCityAudit_CL`** | `TimeGenerated:datetime`, `TeamCityHost:string`, `Action:string`, `ActorId:string`, `TargetId:string`, `TokenRecordId:string`, `OperationResult:string`, `ChangeApproved:bool` |
| **`DockerEvents_CL`** | `TimeGenerated:datetime`, `EventId:string`, `DaemonId:string`, `ContainerId:string`, `EventAction:string`, `Privileged:bool`, `Mounts:dynamic`, `ConfigurationAvailable:bool` |

For HTTP records, `UriPath` is the parsed resource path with token-bearing query strings removed. `HasCmdParameter` comes from content-type-aware form parsing, not a search for `cmd` anywhere in raw traffic. `CommandKind` is a sanitized classification such as `discovery`, `file_read`, `file_write`, `unix_shell`, `docker_run`, `chroot` or `other`; it is not a complete raw command. Missing body inspection means **unknown**, not “no command parameter.” Store a parser/collection status and monitor coverage separately.

For audit records, map real version-specific events to `user_created`, `admin_role_granted` and `token_created`, including the server-recorded result. Populate `ChangeApproved` only from a maintained approval source; null means unknown. `TokenRecordId` is an opaque inventory identifier, never a usable secret.

For Docker, continuously collect lifecycle events and join timely inspected configuration by daemon, container and lifecycle context. `Privileged` comes from inspected/equivalent `HostConfig.Privileged` and remains null when unavailable; each `Mounts` entry includes inspected `Type`, `Source`, `Destination` and `RW`. Set `ConfigurationAvailable=true` only after complete, successfully parsed inspection of the required privilege and mount configuration. An empty `Mounts` array then means an inspected empty list; null, unavailable, non-array or incompletely parsed data means unknown, with false/null availability and a separate collection/parser status. Standard event messages do **not** guarantee these configuration fields. `EventId` must be globally unique and nonempty per normalized daemon event. Inspection confirms configuration, not that a mount occurred; preserve inspection time/provenance in the collector and require reliable association with a start event before assessing startup with those settings. Missing lifecycle records do not establish that a container never started.

#### Q-004 — Uploads and JSP command submissions (D-001/D-003)

```kusto
// PROPOSED AND UNTESTED. Requires the TeamCityHttp_CL contract above.
TeamCityHttp_CL
| where TimeGenerated > ago(1h)
| where Method =~ "POST"
| extend UploadRequest = UriPath endswith "/admin/pluginUpload.html"
| extend JspCommandRequest =
    UriPath matches regex @"(?i)\.jsp(?:/|;|$)"
    and BodyInspectionAvailable == true and HasCmdParameter == true
| where UploadRequest or JspCommandRequest
| extend DetectionCandidate = iif(UploadRequest,
    "PluginUploadRequest", "JspCommandSubmission")
| project TimeGenerated, TeamCityHost, RequestId, SourceIp, ActorId,
          DetectionCandidate, UriPath, CommandKind, BodyInspectionAvailable
```

This intentionally returns upload candidates without presuming maliciousness. Join maintained change/artifact inventories to prioritize, and route incomplete body coverage to a collection-health work item. D-011 needs separate routing features derived from the restricted URI; stripping query strings removes its `jsp=` evidence.

#### Q-005 — Inspected Docker configuration and root-bind status (D-007/D-008)

```kusto
// PROPOSED AND UNTESTED. Configuration states, not proven mounts/host access.
let Events = DockerEvents_CL
    | where TimeGenerated > ago(1h)
    | where EventAction in ("create", "start")
    | extend MountArrayAvailable = isnotnull(array_length(Mounts));
let RootMounts = Events
    | mv-expand Mount = iif(MountArrayAvailable, Mounts, dynamic([]))
    | where tostring(Mount.Type) == "bind"
        and tostring(Mount.Source) == "/"
    | summarize RootMountCount = count() by EventId;
Events
| join kind=leftouter RootMounts on EventId
| extend RootMatchCount = coalesce(RootMountCount, 0)
| extend HostRootBindConfigured = case(
    RootMatchCount > 0, true,
    (ConfigurationAvailable == true and MountArrayAvailable), false,
    bool(null))
| extend RootBindConfigurationStatus = case(
    HostRootBindConfigured == true, "Confirmed",
    HostRootBindConfigured == false, "Not observed",
    "Unknown")
| extend LifecycleObservation = iif(EventAction == "start",
    "Start event observed", "Create event only in this row")
| extend ReviewCategory = case(
    (Privileged == true or HostRootBindConfigured == true), "Risky configuration",
    (ConfigurationAvailable != true or isnull(ConfigurationAvailable)
        or isnull(HostRootBindConfigured) or isnull(Privileged)), "Incomplete inspection",
    "No flagged configuration observed")
| project TimeGenerated, EventId, DaemonId, ContainerId,
          EventAction, LifecycleObservation, Privileged,
          HostRootBindConfigured, RootBindConfigurationStatus,
          ConfigurationAvailable, MountArrayAvailable, ReviewCategory
```

The query retains all three root-bind **configuration** states: **Confirmed** (true) means a valid inspected bind entry has literal source `/`; **Not observed** (false) means complete inspection of an available array found no such entry; **Unknown** (null) means the available data cannot resolve it. A verified positive entry can establish configuration even when other inspection data is incomplete. The zero used for the missing join count only means no matching entry was found; it does not set the configuration state to false. Null/non-array mount data is excluded from expansion and remains unknown, even if availability was incorrectly marked true. An empty array yields false only when complete inspection is confirmed. The ingestion parser must validate individual mount objects and mark partial/malformed inspection incomplete; an array shape check alone cannot establish completeness.

The left join preserves source events with empty/unavailable mounts. All configuration states remain in the output: correlate **Risky configuration** leads with workload approvals and route **Incomplete inspection** to collection-health review. **Not observed** and **No flagged configuration observed** describe this inspected configuration and narrow rule scope; they are not proof of safety or absence of other host-exposing mounts. The query covers literal bind source `/`; canonical path/daemon context handling and policy approval joins remain implementation requirements.

`LifecycleObservation` describes the current event row. A `create` event does not establish startup, and lack of a start row does not establish failure or non-startup. A reliable start event supports startup of the identified container; assessing that it started with the inspected bind additionally requires correctly time-linked configuration evidence. Neither observation proves a successful mounted-tree access, `chroot` or host compromise. Containers with missing lifecycle records cannot appear in this event-based query: monitor collector gaps and reconcile an independent container inventory/inspection source; zero rows do not establish absence of containers or mounts. Monitor incomplete inspection, malformed arrays/objects, empty/duplicate event IDs and collection loss separately.

#### Q-006 — Unapproved or approval-unknown identity changes (D-010)

```kusto
// PROPOSED AND UNTESTED. Normalized actions are not vendor event names.
TeamCityAudit_CL
| where TimeGenerated > ago(1h)
| where Action in ("user_created", "admin_role_granted", "token_created")
| where coalesce(ChangeApproved, false) == false
| extend ApprovalState = iif(isnull(ChangeApproved),
    "Unknown", "NotApproved")
| project TimeGenerated, TeamCityHost, Action, ActorId, TargetId,
          TokenRecordId, OperationResult, ApprovalState
```

Unknown approval and failed operations are investigation leads, not proven unauthorized account creation. Validate inventory and result semantics before elevating confidence. This query implements D-010's unknown/not-approved branch; its approved-but-unexpected-actor branch requires a separately defined baseline/enrichment and is not implemented here. This query introduces no new incident event or ATT&CK assignment.

### 3.4 Linux auditd, Sysmon and runtime collection details

**Auditd templates — proposed, untested, not runnable until placeholders are replaced.** Discover actual paths/UIDs and supported syscalls first; use the host's active architecture, adding 32-bit rules only where supported and necessary. Deploy through normal configuration management with performance/loss monitoring.

```text
# PROPOSED AND UNTESTED audit rules; replace placeholders.
-a always,exit -F arch=b64 -S execve,execveat -F euid=<TEAMCITY_UID> -k tc_exec
-a always,exit -F arch=b64 -S chroot -k tc_chroot
-w <EXISTING_PLUGIN_DIRECTORY> -p wa -k tc_plugin_changes
-w <EXISTING_WEB_RESOURCE_DIRECTORY> -p wa -k tc_web_changes
# Only if this exact file exists in the monitored namespace:
-w /tmp/Creds.txt -p rwa -k tc_creds_file
```

Audit events are multiline: reconstruct `SYSCALL`, `EXECVE`, `PATH`, `CWD` and related records by the same audit event identifier. Preserve source host/boot and timestamps; decode encoded argument fields only in a restricted parser. Distinguish syscall return/success from program exit status: a successful `execve` means a program was loaded, not that its later commands succeeded. A successful `chroot` confirms that syscall's root change, not all-namespace escape.

The UID filter catches processes at that effective UID, not every descendant after escalation. Avoid interactive-only `auid` filters; add suitable privilege-transition/lineage coverage. Existing-path watches do not cover a nonexistent `/tmp/Creds.txt`; assess a narrowly scoped parent-directory/syscall strategy and rename/replacement behaviour. Watching all `/tmp` reads can be noisy and expensive. Monitor dropped events and unsupported syscall/rule failures.

Forward audit records through a configured collector and documented custom parser/table. Sentinel's `Syslog` table can carry forwarded messages if AMA/DCR/routing is configured, but is not inherently structured audit evidence. Do not assume `SyslogMessage` contains all event parts or substitute it for the custom process tables above.

**Windows Sysmon:** Use process GUID/parent GUID, executable, user, hash and timestamp from collected events to reconstruct Windows-side activity. Configure and collect the Sysmon Operational channel using the chosen connector/DCR; validate whether records arrive in `WindowsEvent`, `Event` or a custom table before writing XML/dynamic-field parsing. Neither ordinary Windows Security logs nor Sysmon file creation events prove Linux reads, Docker runtime mounts or remote shell execution.

**Docker/runtime:** Collect daemon service logs and a continuous lifecycle stream, and enrich create/start records promptly using authenticated configuration inspection. Account for `--rm`: exited containers may disappear before inspection. Docker event history is bounded and is not a durable forensic archive; forward it continuously and monitor restart/collection gaps. Capture container ID, daemon/host identity, image digest, effective mounts/privileges and lifecycle times; secure inspection results because environment/configuration data can contain secrets. A container's stdout/stderr can provide output evidence but needs process/request attribution and must not be interpreted as complete control-plane history.

### 3.5 Correlation, alert deployment and validation

Start with hunting and controlled fixtures in a separate test environment, then tune production analytics. No malicious JSP needs to be deployed to validate parsing or alert fields. Use benign representative events and labelled expected outcomes to check approvals, encoding, absent bodies, explicit `--privileged=false`, empty mounts, failed operations, remote daemons, normal builds and collector loss. The fixture results must be documented as future tests, not case outcomes.

For Sentinel scheduled rules, choose cadence/lookback after measuring ingestion delay; a five-minute cadence with a fifteen-minute lookback is only a proposed starting point. Deduplicate using stable request/event IDs rather than emitting one alert per packet or every overlapping query run. Map account/host/IP entities only when their meaning is established; keep workload/container IDs as contextual identifiers. Define an owner, expiry-controlled exceptions and coverage-health alerts for every source.

Correlate upload → resource change → JSP command request → process/file activity → Docker lifecycle/configuration using **host/process/request/container identity plus corrected time**, with a locally validated time window. Clock-adjusted temporal proximity increases confidence but does not establish causality alone. Separate a submitted request, an interpreter start, a file operation, a container start and host-specific access in the incident record. Do not enable automatic containment from a command string or HTTP 200 alone.

Schema/reference starting points, with **no fresh online retrieval or tenant validation claimed**: [DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table), [DeviceFileEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table), [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), [Sentinel Syslog collection](https://learn.microsoft.com/en-us/azure/sentinel/connect-syslog), [Docker events](https://docs.docker.com/reference/cli/docker/system/events/) and [Docker inspect](https://docs.docker.com/reference/cli/docker/container/inspect/). Verify documentation and deployed-version support during implementation.

## 4. Incident response playbook — proposed, not performed

Use the stages below as an enterprise operating sequence. Record who collected each artifact, collection time/tool, original identifiers, hashes and any actions affecting system state. Keep restricted raw evidence separate from sanitized analyst notes. Urgent containment can proceed alongside preservation when ongoing risk warrants it; document the tradeoff rather than delaying necessary action for a perfect collection.

### 4.1 Initial triage

**Collect:** Alert candidate/source record, request or process/container identifiers, parser and sensor status, affected host/service, relevant time window, and approved maintenance/build activity.

**Validate:** Is it a request, a process start or a confirmed operation? Check body truncation/decoding, duplicate traffic, actor context and whether the sensor covers the alleged effect. Pair responses explicitly; HTTP 200 is not command success. Confirm that TeamCity identification and suspicious routing do not establish CVE exploitation.

**Decision/output:** Open an investigation with separate observation, interpretation, confidence and outcome fields. Retain High priority for F-002/F-006/F-007-like requests pending verification; incident severity stays undetermined until scope and impact evidence justify a classification.

### 4.2 Scope identification

**Collect:** TeamCity server/agent inventory, actual release and mitigation state, exposure/management paths, service identities, plugin/resource locations, build/deployment dependencies, account/token inventories, Docker clients/daemon endpoints and containers. Hunt the case URI/archive/path as scoped indicators, then expand to equivalent behaviour and artifacts.

**Validate:** Establish client/proxy/server/daemon topology and clocks; identify where `/tmp/Creds.txt` and `/host` resolve. Determine authorization, account/token scope and which build secrets/artifacts were reachable. Distinguish mirrored/NAT views and repeated screenshots from separate actions.

**Decision/output:** Maintain confirmed affected assets separately from possibly exposed assets. Broaden hunts across agents and downstream services only with the relevant identity/network relationships; do not assume host compromise from a Docker flag.

### 4.3 Evidence preservation

**Collect:** Original source capture if obtainable, raw access/audit/application logs, paired response bodies, upload archive, plugin inventory/artifacts, process trees and available memory/volatile state, file metadata/restricted contents, Docker events/configuration, image digests, namespaces/mounts and host access records. Preserve identities/token metadata without distributing token values.

**Validate:** Hash preserved artifacts and document provenance, capture clock basis and request/frame associations. Preserve both denied and successful operation records. Seek prior/current file state and later readback; the earlier read cannot prove the later write. An acquired response body still needs attribution and interpretation.

**Decision/output:** Secure evidence with access controls and a documented handling record. Capture volatile runtime state before restart/removal when safe; `--rm`, cleanup and revocation can remove evidence. Avoid installing new collection agents retrospectively and representing their data as historical coverage. Do not execute suspicious JSPs/archives on the affected server.

### 4.4 Containment

**Collect:** Current sessions, service connections, pending builds, active containers, network dependencies and minimal volatile identifiers/configuration before disruptive changes where feasible.

**Validate:** Confirm unauthorized functionality or credible ongoing risk, and identify the business impact of isolating the control server versus an agent/daemon. Determine whether tokens/accounts or downstream credentials are genuinely implicated, rather than rotating solely because a filename contains “Creds.”

**Action/output:** Under the enterprise incident process, restrict suspicious JSP/plugin access and administrative routes, isolate affected hosts or network paths, stop unapproved daemon access and revoke established unauthorized identities/tokens. Coordinate build/deployment disruption with service owners. Prefer targeted controls where adequate; if immediate risk requires stopping a container/host, document any lost volatile evidence. Record action, time, scope and rollback conditions.

### 4.5 Eradication

**Collect:** Confirmed unauthorized artifacts, altered plugins/configuration, identity changes, persistence evidence and affected build/deployment material.

**Validate:** Compare with trusted plugin packages, baseline configuration and approved identity inventories. Verify how unauthorized access occurred before attributing CVE-2024-27198. Confirm effective fixes against the installed version and vendor guidance.

**Action/output:** Remove verified unauthorized resources/identities after preservation; repair the access path, patch/mitigate as applicable and rotate affected secrets according to established exposure. If privileged host compromise is corroborated or trust cannot be restored, rebuild affected systems from trusted sources and review dependent artifacts. Do not assume removing one JSP restores trust in a compromised CI environment.

### 4.6 Recovery

**Collect:** Clean release/plugin manifests, restored configurations, identity and secret changes, image digests, revised service/Docker permissions and validation results.

**Validate:** Test necessary build/deployment functions, vendor fixes, administrative restrictions, effective mount/privilege policy and logging. Verify restored artifacts and critical pipelines against trusted sources; confirm normal service-account activity and absence of the known unauthorized resources.

**Action/output:** Restore connectivity and workloads in stages with service-owner acceptance and a rollback plan. Establish a new approved baseline only after confirming its provenance. Do not interpret a quiet dashboard as recovery without checking sensor/collector health.

### 4.7 Post-incident monitoring

**Collect:** Continued upload/resource/identity events, command-interface requests, service process/file activity, Docker configuration/lifecycle events and ingestion-health measurements.

**Validate:** Look for recurrence or alternative paths/identities across the scoped environment; correlate approved changes and avoid suppressing new malicious activity behind a broad build allowlist. Measure time to detect, missing fields, false positives and coverage gaps.

**Action/output:** Tune rules and exceptions with documented tests; update baselines and response procedures. Reassess incident severity using confirmed results, scope and impact. Close remaining questions explicitly as resolved or unverified, including authorization, exploitation, installation, command/file effects, Docker startup and host access.

## 5. Prioritized defensive recommendations

These priorities rank practical control work; they do not change the incident's undetermined severity or the findings' response priorities. P1 controls address the highest-risk requested access and the ability to verify outcomes; P2 reduces follow-on exposure and improves sustainable coverage.

| Priority | Recommendation and practical action | Reasoning / implementation check |
|---|---|---|
| **P1** | **TeamCity patching/vulnerability management:** verify the actual release, security fixes, mitigations and exposure; update to a currently supported vendor-fixed release after preserving relevant evidence and planning operational changes | F-001 advertises an older specific release but does not prove effective vulnerability. Validate inventory and fix state, not banner text alone; do not treat 2023.11.4 as a current target release. |
| **P1** | **Plugin restrictions and integrity monitoring:** limit upload/install authority to approved operators; require trusted reviewed packages/hashes, documented changes and monitoring of archives plus expanded resources | F-002 requests a reusable command interface. Validate both authorization and what reached disk/activation; an upload restriction without artifact monitoring leaves outcome gaps. |
| **P1** | **Administrative account/token monitoring:** centralize supported audit events and regularly reconcile privileged identity/token inventories; limit scope/lifetime and prohibit shared administrative tokens | Enables attribution of unapproved administrative changes without asserting such creation occurred in this case. Verify audit completeness and alert without exposing token values. |
| **P1** | **Service-account least privilege:** separate the TeamCity control service from build/deployment identities; limit filesystem writes, secrets and process privileges to required functions | A functioning interface inherits reachable permissions. Rootful Docker group/socket access is ordinarily highly privileged and can undermine nominal service-account restrictions. Baseline necessary server versus agent shell activity. |
| **P1** | **Restrict Docker daemon access:** remove unnecessary CI-server socket/group access; use authenticated, authorized remote access where needed, workload separation and policy controls | Both Docker requests depend on daemon control. Inventory the actual daemon, enforce who may create containers and review direct API paths; a local firewall alone does not restrict an accessible Unix socket. |
| **P1** | **Avoid privileged containers:** deny privileged mode by default through supported runtime/API policy; review narrowly scoped alternatives and expiring exceptions | F-006 explicitly requests weakened isolation. Validate effective runtime configuration, including devices/capabilities, rather than checking CLI text alone. |
| **P1** | **Restrict host filesystem mounts:** deny host-root bind mounts and unnecessary sensitive paths; use minimal approved mounts and read-only access where functional | F-007 requests host-root access without privileged mode. Check daemon-side resolved source, effective read/write access and alternate syntax; forbidding `--privileged` alone does not address this request. |
| **P1** | **Endpoint detection and durable centralized logging:** cover the control server, agents and daemon hosts with supported process/file telemetry, audit and continuous runtime collection | Correlated endpoint/runtime evidence is needed to distinguish requests from effects. Validate body/configuration coverage, retention, clocks, parsing, loss and `--rm` races; deploying a connector does not guarantee collection. |
| **P2** | **Network segmentation and egress controls:** restrict administration to management paths; separate servers, agents, Docker control and deployment targets; allow only necessary outbound destinations | Limits reachable assets if service access succeeds. Test real CI dependencies, proxy/NAT paths and remote daemons; segmentation does not remedy executable malicious content or overly broad local privileges. |
| **P2** | **Operational baselines and tested response:** document normal plugin/job/container/identity changes, maintain clean artifact inventories and validate detection/response steps in controlled exercises | Normal CI shell/Docker activity creates substantial false positives. Narrow workload-based exceptions and a tested preservation plan improve usable detections without inventing confidence in the untested examples here. |

## 6. Operational lessons for an entry-level SOC analyst

- **Network forensics:** Reassemble and decode a complete request before describing a command. A selected background packet can differ from a stream footer's body reference. Repeated or mirrored views are not independent actions; screenshot labels and HTTP Date headers do not establish the capture clock.
- **Endpoint/network correlation:** A request points to an intended action. Correlate host identity, service lineage, file operations and runtime events to evaluate effects; IP/time proximity alone is insufficient. Record which sensors were actually enabled so missing telemetry is not mistaken for a failed action.
- **Execution evidence:** `cmd=ls`, `bash -c`, HTTP 200 and response length are different observations. A process start establishes a launch, not final command success. A file open/write needs result and content/state context; a read before a write cannot verify a later change.
- **Container security:** Keep privileged mode and host-root mounting separate. Docker clients can address another host, and `chroot` changes a filesystem root rather than proving all-namespace escape. Container IDs, lifecycle and effective settings are necessary to move beyond command text.
- **ATT&CK mapping:** Map the specific behaviour and preserve status/confidence. Explicit `bash -c` supports Unix Shell; `ls` supports Discovery without identifying an interpreter. Intended file manipulation and escape remain tentative, and a filename or proposed identity rule does not justify additional case techniques.
- **Evidence confidence and limitations:** High confidence in readable request text is not High confidence in compromise. State observations, interpretations and unverified outcomes separately; preserve secrets and provenance without overstating authenticity. Response urgency can be High while incident severity remains undetermined.

## 7. Implementation readiness and remaining questions

This document is a practical design and playbook, **not a tested detection package**. Before deployment, establish actual logging/version support, host/account/path inventories, schemas, parser secret handling, event coverage, approvals, runtime enrichment and latency/retention. Validate each candidate against representative benign and suspicious fixtures and record the results; no precision, recall or case-PCAP coverage is claimed.

The incident questions remain whether the activity was authorized, whether the instance was effectively vulnerable, whether the upload became executable, whether commands/file operations succeeded, whether containers started, which daemon host was targeted, and whether any host access or business impact occurred. **No successful exploitation, webshell installation, command execution, credential theft, Docker deployment or host compromise is established by this reporting task.**

Only this document was created. Existing investigation reports, evidence documents, manifests and screenshots were left unchanged. No detections were deployed, response actions performed, final README created, or material published/uploaded.
