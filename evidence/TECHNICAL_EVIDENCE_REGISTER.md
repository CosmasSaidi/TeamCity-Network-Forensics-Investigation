# JetBrains TeamCity Technical Evidence Register

## Basis and limits

This register documents seven observations inherited from the previous screenshot visual audits and the references supplied in this investigation. **No screenshots or source packets were independently re-inspected for this register.** The supporting filenames and evidence IDs were checked against [SCREENSHOT_MANIFEST.csv](SCREENSHOT_MANIFEST.csv), and [PRESERVATION_NOTES.md](PRESERVATION_NOTES.md) was read. The manifest records 70 screenshots; its hashes identify original screenshot files, not packet captures or successful execution.

Evidence IDs below are the existing screenshot IDs from the manifest. Multiple screenshots can support one observation. Supporting screenshots are selected references, not an exhaustive list of repeated views. Credential values and authentication tokens are redacted or omitted.

Filename timestamps identify screenshots and preserve their chronological order. They are not packet timestamps. Numeric Wireshark Time values are reproduced from the previous audit without assuming their time origin or timezone. An HTTP Date header is recorded separately as a server-supplied timestamp.

**Confidence:** High means the inherited audit describes clearly readable packet text or an explicit identifier. Moderate means an association relies on the surrounding filtered view or stream footer rather than an independently checked packet record. Confidence applies to the stated observation, not to command execution, compromise, or authenticity. Unverified outcomes remain unverified regardless of confidence in request text.

## 1. TeamCity version response

- **Evidence ID / supporting screenshot:** EV-008 — `Screenshot From 2026-11-03 01-41-04.png`.
- **Packet and stream:** Frame **24711**, HTTP/TCP stream **364**. Wireshark Time **1054.290142**.
- **Directly visible, inherited from audit:** An HTTP **200** response contains XML advertising TeamCity version **2023.11.3**, build **147512**. The earlier audit records HTTP Date **Sun, 30 Jun 2024 08:02:49 GMT**. The audit identifies this view as the clearer response-to-packet linkage.
- **Reasonable inference:** The responding endpoint disclosed these TeamCity version/build values.
- **Unverified:** Independent validation of the running installation; the exact triggering request in this screenshot; vulnerability exploitation. A version string alone does not establish exploitation of CVE-2024-27198.
- **Confidence / justification:** **High for the advertised version/build and inherited frame/stream association:** the earlier audit describes readable XML and explicit references. No independent image or packet verification was performed here.

## 2. Multipart plugin upload request

- **Evidence ID / supporting screenshot:** EV-014 — `Screenshot From 2026-11-03 02-10-16.png`.
- **Packet and stream:** Frame **24825**, HTTP/TCP stream **364**. Wireshark Time **1071.315015**.
- **Directly visible, inherited from audit:** Multipart **POST** to `/admin/pluginUpload.html`, naming **`NSt8bHTg.zip`**. The upload view includes `NSt8bHTg.jsp` and JSP content accepting a **`cmd`** parameter, including `request.getParameter("cmd")`. Authentication/CSRF values are omitted from this register.
- **Reasonable inference:** A plugin/archive upload carrying command-handling JSP content was submitted. This supports an attempted upload of a webshell-capable component.
- **Unverified:** Upload acceptance, server-side storage, plugin installation or activation, and successful execution of the JSP. Later requests to a matching path do not by themselves establish installation success.
- **Confidence / justification:** **High for the submitted filename and visible JSP content:** the inherited audit describes readable multipart content associated with frame 24825 and stream 364. No installation outcome is established by this observation.

## 3. Webshell request containing `ls`

- **Evidence IDs / supporting screenshots:** EV-060 — `Screenshot From 2026-11-04 20-50-14.png`; EV-061 — `Screenshot From 2026-11-04 20-51-08.png`; EV-062 — `Screenshot From 2026-11-04 20-53-31.png` (clearest decoded form view).
- **Packet and stream:** Frame **25572**. **Stream number not established by these supporting views.** Wireshark Time **1122.563990**. Reassembly: **25566 (527 bytes) + 25572 (6 bytes) = 533 bytes**.
- **Directly visible, inherited from audit:** Client **POST** to `/plugins/NSt8bHTg/NSt8bHTg.jsp`, from `23.158.56.196` to `172.31.25.119`. The six-byte form body is **`cmd=ls`**; EV-062 explicitly expands the decoded `cmd` value as **`ls`**.
- **Reasonable inference:** A directory-listing command was submitted to the JSP endpoint. The URI and parameter match the command-handling interface described in item 2.
- **Unverified:** A corresponding response, directory listing, exit status, actual execution, or whether this was the first command in the complete capture.
- **Confidence / justification:** **High for command submission:** both packet bytes and the expanded form value are recorded by the previous audit. The supporting views establish no execution outcome.

## 4. Credential-file read request

- **Evidence ID / supporting screenshot:** EV-065 — `Screenshot From 2026-11-04 20-58-29.png`.
- **Packet and stream:** Frame **26895**. **Stream number not visible/established.** Wireshark Time **1524.276831**. Reassembly: **26889 (528 bytes) + 26895 (26 bytes) = 554 bytes**.
- **Directly visible, inherited from audit:** Client **POST** to `/plugins/NSt8bHTg/NSt8bHTg.jsp`. Complete visible form body: **`cmd=cat+%2Ftmp%2FCreds.txt`**. The expanded command is **`cat /tmp/Creds.txt`**.
- **Reasonable inference:** The request attempts to read the named credential file through the JSP command parameter.
- **Unverified:** Whether the file existed, its contents, the corresponding response, command execution, or disclosure/compromise of credentials. A search field containing `Creds.txt` is analyst input and does not establish file contents.
- **Confidence / justification:** **High for the requested path and command:** the inherited audit records matching packet bytes, decoded form text, and reassembly identifiers. No returned file contents were visible.

## 5. Credential-file write request

- **Evidence ID / supporting screenshot:** EV-066 — `Screenshot From 2026-11-04 20-59-56.png`.
- **Packet and stream:** Frame **31123**. **Stream number not visible/established.** Wireshark Time **1721.175300**. TCP payload **99 bytes**; reassembly **31117 (528 bytes) + 31123 (99 bytes) = 627 bytes**.
- **Directly visible, inherited from audit:** The selected client **POST** to `/plugins/NSt8bHTg/NSt8bHTg.jsp` contains the command below. Command syntax is preserved; all credential values are redacted.

```sh
bash -c 'echo "username:[REDACTED],password:[REDACTED]" > /tmp/Creds.txt'
```

- **Reasonable inference:** The request intends to write attacker-supplied credential fields into `/tmp/Creds.txt`. Shell redirection `>` would create or truncate the target if the command executed successfully with sufficient access; this describes intended semantics, not an observed filesystem change.
- **Unverified:** Execution, write success, prior file contents, a subsequent read confirming replacement, corresponding server response, or use of the supplied credentials. Frame **31124**, Time **1721.175329**, is visible only as a client POST to `172.17.0.2`; its body is unopened and it is not a server response.
- **Confidence / justification:** **High for the command structure and intended write:** the previous audit read the selected packet bytes and expanded form value. No successful credential change is established.

## 6. Docker request using privileged mode

- **Evidence IDs / supporting screenshots:** EV-068 — `Screenshot From 2026-11-04 21-18-40.png`; EV-069 — `Screenshot From 2026-11-04 21-19-31.png` (repeated request view). EV-070 — `Screenshot From 2026-11-04 21-24-13.png` supports stream membership only for this item.
- **Packet and stream:** Frame **32002**, Wireshark Time **2039.893932**. **HTTP/TCP stream 601**, established in the inherited audit by frame 32002 appearing in EV-070's `tcp.stream eq 601` background packet list. Reassembly: **31996 (528 bytes) + 32002 (43 bytes) = 571 bytes**.
- **Directly visible, inherited from audit:** Selected frame 32002 is a client **POST** to `/plugins/NSt8bHTg/NSt8bHTg.jsp`. The entire **43-byte** form body and decoded command are visible:

```text
cmd=docker+run+--rm+-it+--privileged+ubuntu
```

```sh
docker run --rm -it --privileged ubuntu
```

- **Reasonable inference:** A request attempts to start an Ubuntu Docker container with privileged mode, automatic removal and interactive terminal flags.
- **Unverified:** Docker availability, command execution, successful container startup, exit status or host compromise. Frame **32003**, Time **2039.893977**, is visible only as another client POST to `172.17.0.2`; its payload and stream number are not established. Frames **32008 (2039.940450)** and **32010 (2039.940483)** appear as HTTP **200**, `text/html`, server responses in the packet list; their response bodies and explicit request associations were not inspected.
- **Confidence / justification:** **High for frame 32002's command/body; Moderate for stream membership and response association:** command text is explicit in the inherited audit, but stream membership is derived from the later filtered background list. Nearby HTTP 200 rows provide no execution proof.

## 7. Docker request mounting and selecting the host filesystem

- **Evidence ID / supporting screenshot:** EV-070 — `Screenshot From 2026-11-04 21-24-13.png`.
- **Packet and stream:** **HTTP/TCP stream 601**. The Follow HTTP Stream footer references **Packet 32111**; its packet-list Time is **2065.593291**. The background selected frame is **32010**, which must not be substituted for the footer's request reference.
- **Directly visible, inherited from audit:** The stream shows the entire **62-byte** form body, decoded below. The corresponding request line and part of the headers are outside the viewport; the complete HTTP request is not visible.

```text
cmd=docker+run+--rm+-it+-v+%2F%3A%2Fhost+ubuntu+chroot+%2Fhost
```

```sh
docker run --rm -it -v /:/host ubuntu chroot /host
```

The server response immediately following that body in the stream shows **HTTP/1.1 200**, `TeamCity-Node-Id: MAIN_SERVER`, `Content-Type: text/html;charset=utf-8`, `Content-Length: 4`, and HTTP Date **Sun, 30 Jun 2024 08:19:40 GMT**. No readable response-body output or response frame identifier is visible.

- **Reasonable inference:** The submitted command attempts to bind-mount `/` into the container at `/host` and run `chroot /host`. These are intended host-filesystem access semantics if Docker executes successfully; they do not establish that host access occurred.
- **Unverified:** An independently checked frame-to-body mapping, full request headers, exact response frame mapping, response body, command exit status, mount/chroot success, or host compromise. HTTP 200 and a four-byte advertised response length do not prove shell execution.
- **Confidence / justification:** **High for the stream number, body and displayed response headers; Moderate for the body-to-frame association:** the inherited audit identifies packet 32111 through the stream footer rather than expanded packet details. Execution remains unverified.

## Missing evidence and inconsistencies requiring review

1. **Packet validation and time basis:** An independently checked source capture is needed to confirm frame/stream mappings, full reassembly, request-response pairing, and the numeric Time column's origin/timezone. Screenshot filename dates and filesystem modification timestamps cannot supply packet event times. The HTTP Dates are server-provided values, not independent clock validation.
2. **Version and exploitation:** The version response documents advertised values. Evidence establishing the triggering request, actual vulnerable configuration and exploitation is still needed before attributing successful CVE exploitation.
3. **Upload outcome:** No supporting response or server-side artifact establishes upload acceptance, plugin installation/activation, or successful JSP execution.
4. **Shell and credential outcomes:** Returned `ls` output, returned `/tmp/Creds.txt` contents, write status, and a subsequent read verifying a file change are missing from the selected references. No credential compromise or successful replacement is established.
5. **Paired request rows:** Frames 31124 and 32003 are client POST entries, not responses. Their bodies and stream identifiers were not visible. Do not assume their contents solely from their proximity to frames 31123 and 32002.
6. **Two distinct Docker requests:** Frame 32002 contains the 43-byte privileged-mode body; packet 32111 is associated with the 62-byte bind-mount/chroot body. Assigning the host-mount command to frame 32002 would contradict the audit. No command output establishes successful Docker execution or host compromise.
7. **Response and selection ambiguity:** Frames 32008/32010 have packet-list HTTP 200 status evidence. The host-mount response in EV-070 lacks a visible frame identifier. EV-070's background selection of 32010 does not identify its foreground command; the stream footer references 32111. Explicit packet-level linkage and the actual response bodies need review.
8. **Missing stream identifiers:** No supporting view establishes stream numbers for frames 25572, 26895, 31123, 31124 or 32003. Do not extend stream 364 or 601 to those frames without evidence.
9. **Lab answers and repeated views:** EV-067 (`Screenshot From 2026-11-04 21-05-23.png`) contains lab questions and credential answer fields, not packet proof. Earlier analyst search inputs and repeated views likewise cannot establish file contents or execution. EV-069 repeats EV-068's Docker request; it is not an independent event.

This register makes no claim of formal chain of custody or successful compromise. Original screenshots, the manifest and preservation notes were preserved without content changes.
