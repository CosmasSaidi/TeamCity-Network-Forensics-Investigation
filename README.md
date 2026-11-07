# JetBrains TeamCity Network Forensics Investigation

**CyberDefenders lab — JetBrains TeamCity investigation**

I investigated suspicious TeamCity activity using preserved Wireshark screenshots from a CyberDefenders lab. The selected traffic shows a plugin upload containing JSP command-handling code, followed by requests for directory listing, file access and Docker operations.

The **[full investigation report](report/INVESTIGATION_REPORT.md)** contains the detailed analysis and recommendations.

## Investigation overview

The evidence consists of 70 preserved screenshots showing packet details, HTTP streams, TCP reassembly and decoded forms. The source capture, server logs and runtime artifacts were not independently acquired or validated.

The main service and request details are:

| Detail | What I observed |
| --- | --- |
| Request-source IP | **23.158.56.196**, visible sending the selected JSP POST in frame 25572; an observed request-source IP, not established actor attribution |
| Destination in that request | **172.31.25.119**; its relationship to other internal addresses and HTTP Host values remains unresolved |
| TeamCity version | **2023.11.3, build 147512**, advertised in the XML response at frame 24711 |
| Suspected command interface | **/plugins/NSt8bHTg/NSt8bHTg.jsp**, targeted by POSTs carrying **cmd** parameters |

**CVE-2024-27198** remains an investigation hypothesis based on the advertised version and unusual request routing.

## Key findings

These seven findings distinguish observed requests from unverified outcomes.

| Finding | What I observed | What remains unverified |
| --- | --- | --- |
| **F-001** — Identification and potential exposure | TeamCity version/build disclosure with unusual request routing | Vulnerable configuration, authentication bypass and exploitation |
| **F-002** — Suspicious plugin upload | Multipart request naming **NSt8bHTg.zip**, with JSP command-handling code | Acceptance, installation, activation and persistence |
| **F-003** — Directory-discovery request | **cmd=ls** submitted to the matching JSP path | Executed command or returned listing |
| **F-004** — File-read request | **cat /tmp/Creds.txt** submitted | File existence, credential contents, successful read or data receipt |
| **F-005** — File-write request | **bash -c** request to redirect credential-labelled text to **/tmp/Creds.txt** | File creation/modification, credential use or account-password change |
| **F-006** — Privileged Docker request | **docker run --rm -it --privileged ubuntu**; no root bind or chroot | Container startup or granted privileges |
| **F-007** — Host-root bind/chroot request | **docker run --rm -it -v /:/host ubuntu chroot /host**; no privileged flag | Container startup, mount/chroot success, host access or escape |

F-002, F-006 and F-007 have **High provisional response priority** because the requested capabilities could have serious consequences. The other findings have Medium priority. These priorities describe investigation urgency, not confirmed incident impact.

## Observed Request Sequence

The selected packet events appear in this order. **Wireshark Time values are copied as displayed.** Their interpretation as relative seconds is provisional because the display mode and reference point were not verified.

| Event | Frame reference | Wireshark Time | Supporting evidence |
| --- | --- | --- | --- |
| TeamCity identification | 24711 | 1054.290142 | EV-008 |
| Plugin upload submission | 24825 | 1071.315015 | EV-014 |
| Directory-listing submission | 25572 | 1122.563990 | EV-062; EV-060/EV-061 supporting views |
| File-read submission | 26895 | 1524.276831 | EV-065 |
| File-write submission | 31123 | 1721.175300 | EV-066 |
| Privileged Docker submission | 32002 | 2039.893932 | EV-068; EV-069 repeated view |
| Root-bind/chroot submission | Footer packet 32111 | 2065.593291 | EV-070 |

The selected sequence does not establish the complete activity history. The file-read request came before the write and cannot verify the later write.

For F-007, EV-070 links the command body to footer packet **32111**. Its background selection is **32010**, a different reference. The [detailed timeline](evidence/ATTACK_TIMELINE.md) explains these associations and the timing limits.

## MITRE ATT&CK

These mappings describe observed requests and tentative interpretations. Confidence applies to the observation or interpretation, not to successful execution.

| Technique | Assessment and confidence |
| --- | --- |
| **T1190 — Exploit Public-Facing Application** | Tentative exploitation hypothesis; **Low** |
| **T1505.003 — Server Software Component: Web Shell** | Tentative placement/use interpretation; **Moderate** |
| **T1083 — File and Directory Discovery** | Observed **ls** submission; **High** |
| **T1059.004 — Command and Scripting Interpreter: Unix Shell** | Observed explicit **bash -c** request; **High** |
| **T1565.001 — Data Manipulation: Stored Data Manipulation** | Tentative intended file manipulation; **Moderate**, no proven change or achieved impact |
| **T1610 — Deploy Container** | Observed attempts; F-006 **High command-fit/Moderate stream association**, F-007 **Moderate overall** |
| **T1611 — Escape to Host** | Tentative F-007 host-access interpretation; **Moderate** |

T1611 applies only to F-007's tentative host-access interpretation. F-006's privileged flag alone does not justify it. The file-read request has no assigned technique. Several mappings describe different aspects of the same packet events.

The [detailed ATT&CK mapping](evidence/MITRE_ATTACK_MAPPING.md) contains the supporting evidence and reasoning.

## Detection engineering

The report develops **11 detection opportunities** across four areas:

- **TeamCity requests and resources:** suspicious plugin uploads, unexpected JSP resources, POSTs carrying command parameters, and unusual routing or version-information access.
- **Shell and file activity:** Unix shell starts associated with the TeamCity identity or verified process ancestry, and separate read/write activity involving `/tmp/Creds.txt`.
- **Docker and chroot:** unexpected client or daemon activity, privileged container requests/configuration, host-root bind mounts, and chroot requests or system calls.
- **Administrative identities:** account, role and token changes. This is preventive monitoring; no such change is established in the case.

**All detection logic and the six KQL examples are proposed and untested.** They were not tested against the case PCAP or an enterprise SIEM workspace and are not production-ready. Native Defender process/file telemetry and the assumed custom Sentinel HTTP, Docker and audit tables need different collection setups; example tables and fields must be verified before use.

Command-line or regex matches do not verify that Docker accepted an option. The root-bind query's **Confirmed / Not observed / Unknown** states concern inspected configuration; container lifecycle and host-access results require separate evidence.

The [detection and response document](report/DETECTION_AND_RESPONSE.md) contains the full catalog, KQL examples, and requirements for parsing, baselines, approval context, process ancestry, lifecycle correlation and testing.

## Evidence and screenshots

The selected packet and stream views are shown below. Supporting observations are in the [evidence register](evidence/TECHNICAL_EVIDENCE_REGISTER.md); the [screenshot inventory](evidence/SCREENSHOT_MANIFEST.csv), [preservation notes](evidence/PRESERVATION_NOTES.md) and [figure records](report/figures/DERIVATIVE_MANIFEST.csv) contain the detailed records.

### F-001 — TeamCity identification

![F-001: TeamCity version response, EV-008, frame 24711](report/figures/F-001_EV-008.png)

*EV-008 / frame 24711 / stream 364: XML version/build response.*

### F-002 — Plugin upload

![F-002: Plugin archive and JSP command parameter, EV-014, frame 24825](report/figures/F-002_EV-014.png)

*EV-014 / frame 24825 / stream 364: multipart upload with JSP cmd-handling code.*

### F-003 — Directory discovery

![F-003: Submitted cmd=ls, EV-062, frame 25572](report/figures/F-003_EV-062.png)

*EV-062 / frame 25572: cmd=ls in packet bytes and the decoded form.*

### F-004 — File-read request

![F-004: Submitted cat /tmp/Creds.txt, EV-065, frame 26895](report/figures/F-004_EV-065.png)

*EV-065 / frame 26895: decoded file-read command. The analyst's search text is not evidence of file contents.*

### F-005 — File-write request

![F-005: Redacted shell/redirection request, EV-066, frame 31123](report/figures/F-005_EV-066.png)

*EV-066 / frame 31123: bash -c and output redirection in the decoded request.*

### F-006 — Privileged Docker request

![F-006: Privileged-only Docker submission, EV-068, frame 32002](report/figures/F-006_EV-068.png)

*EV-068 / frame 32002: the 43-byte command body. Nearby HTTP 200 rows have no verified request pairing.*

### F-007 — Host-root bind/chroot request

![F-007: Root-bind/chroot body, EV-070, footer packet 32111](report/figures/F-007_EV-070.png)

*EV-070 / stream 601 / footer packet 32111: root-bind/chroot body with four advertised response bytes and no readable command output.*

## Incident response and lessons

Follow-up would pair HTTP responses with requests and check TeamCity plugin/audit records, process/file activity, and Docker lifecycle/configuration. These records could establish what ran and where `/tmp/Creds.txt` and the requested host mount resolved.

The recommendations focus on verifying TeamCity fixes, restricting plugin administration, monitoring accounts and tokens, limiting service privileges and Docker access, and avoiding unnecessary privileged containers or host-root mounts. Centralized endpoint, application and runtime logs would support that investigation. Segmentation and egress controls need to account for actual CI dependencies.

The seven-stage response playbook covers **triage → scoping → preservation → containment → eradication → recovery → monitoring**. These are recommendations; I did not perform containment, credential rotation, eradication or recovery during the lab.

The two Docker requests made it important to assess privileged mode and host-root mounts separately. Correlation also requires request, host, process and container identities; matching addresses or nearby timestamps alone cannot establish the connection.

## Investigation limitations

The findings table records the unverified outcomes. The remaining evidence gaps and interpretation limits are:

- **Missing results:** matched response bodies, deployed artifacts, process/file-state evidence and Docker runtime records are missing. HTTP 200 alone does not establish command success.
- **Access context and topology:** actor identity, authorization and effective patch state remain unresolved. The source IP is an observed packet address, not actor attribution. Packet addresses and HTTP Host values do not establish how the observed systems were connected.
- **Docker boundaries:** the daemon's location and the starting privileges/namespaces remain unknown. Chroot changes a process's filesystem root; it does not establish escape from every namespace.
- **Timing and scope:** screenshot dates, filesystem timestamps and HTTP Date headers do not establish absolute event times or incident duration. The affected scope remains unverified. Screenshot hashes support file integrity but do not independently authenticate the original source traffic.

Missing corroboration does not prove that an attempted action failed or that the system was safe. **Incident severity remains undetermined, and compromise is unverified.** Stronger conclusions require the result evidence identified in the report.

## Repository navigation

| Document | Contents |
| --- | --- |
| [Full investigation report](report/INVESTIGATION_REPORT.md) | Complete case analysis |
| [Executive summary](report/EXECUTIVE_SUMMARY.md) | Case overview |
| [Technical findings](report/TECHNICAL_FINDINGS.md) | Detailed findings |
| [Detection and response](report/DETECTION_AND_RESPONSE.md) | Detection catalog and response playbook |
| [Evidence register](evidence/TECHNICAL_EVIDENCE_REGISTER.md) | Observations and supporting sources |
| [Request timeline](evidence/ATTACK_TIMELINE.md) | Packet order and associations |
| [ATT&CK mapping](evidence/MITRE_ATTACK_MAPPING.md) | Technique assessments and rationale |
| [Screenshot inventory](evidence/SCREENSHOT_MANIFEST.csv) | Original screenshot records |
| [Preservation notes](evidence/PRESERVATION_NOTES.md) | Evidence handling notes |
| [Figure records](report/figures/DERIVATIVE_MANIFEST.csv) | Figure and source references |
