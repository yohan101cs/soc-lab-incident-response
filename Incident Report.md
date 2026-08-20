# Incident Report: Malicious Executable Execution and C2 Callback

**Environment:** SOC Home Lab (isolated internal network)
**Analyst:** Yohan
**Date of Incident:** August 19, 2026
**Status:** Contained / Eradicated

---

## 1. Executive Summary

A disguised malicious executable (`NotSucpicious.pdp.exe`) was downloaded and executed on the Windows 10 lab endpoint (`192.168.20.10`). Upon execution, the file established a reverse command-and-control (C2) connection to an external host (`192.168.20.11`) on TCP port `4444` and was used to run discovery commands (`net user`, `net localgroup`, `ipconfig`). The activity was identified using Sysmon telemetry ingested into Splunk. The threat was contained by blocking outbound traffic to the attacker's IP/port via the Windows Firewall, and eradicated by terminating the malicious process.

This incident was simulated in a fully isolated lab environment for the purpose of practicing detection engineering and incident response.

---

## 2. Environment Overview

| Host | Role | IP Address |
|---|---|---|
| Windows 10 VM | Victim / Endpoint | 192.168.20.10 |
| Kali Linux VM | Attacker | 192.168.20.11 |

- Both VMs isolated on a VirtualBox **Internal Network** (no internet or host-machine connectivity)
- **Sysmon** installed on the Windows VM for endpoint telemetry
- **Splunk Enterprise** installed as the SIEM, with the **Splunk Add-on for Sysmon** for log parsing
- Baseline snapshot taken prior to the exercise for recovery

---

## 3. Timeline of Events

| Time (2026-08-19) | Event |
|---|---|
| 20:48:21.336 | `NotSucpicious.pdp.exe` executed, spawns `cmd.exe` |
| 20:48:26.745 | `cmd.exe` spawns `net.exe user` |
| 20:48:31.409 | `cmd.exe` spawns `net.exe localgroup` |
| 20:48:35.912 | `cmd.exe` spawns `ipconfig.exe` |
| 20:54:11.875 | `cmd.exe` spawns `ipconfig.exe` (second run) |
| 21:03:36.884 | `cmd.exe` spawns `net.exe localgroup` (second run) |
| 21:03:41.609 | `cmd.exe` spawns `ipconfig.exe` (third run) |
| — | Outbound connection observed: `192.168.20.10` → `192.168.20.11:4444` (established) |
| — | Windows Firewall outbound rule created, blocking TCP 4444 to 192.168.20.11 |
| — | Re-attempted C2 connection from attacker VM — Meterpreter session immediately closed (`Reason: Died`), confirming containment |
| — | Malicious process terminated via Task Manager |

*Times sourced from Sysmon Event ID 1 telemetry queried in Splunk.*

---

## 4. Indicators of Compromise (IOCs)

| Type | Value |
|---|---|
| File name | `NotSucpicious.pdp.exe` |
| File path | `C:\Users\yohan\Downloads\NotSucpicious.pdp.exe` |
| File size | 7,680 bytes |
| File type | PE32+ executable for MS Windows, x86-64 |
| C2 destination IP | 192.168.20.11 |
| C2 destination port | 4444/TCP |
| Parent process | `NotSucpicious.pdp.exe` |
| Child process | `cmd.exe` |
| Grandchild processes | `net.exe` (user, localgroup), `ipconfig.exe` |

---

## 5. Identification

Detection was performed using Splunk searches against Sysmon-sourced telemetry (index `endpoint`).

**Process creation (Sysmon Event ID 1)** — traced using the process's `process_guid`:
```
index=endpoint {process_guid}
| table _time, ParentImage, Image, CommandLine
```
This revealed the full process lineage: `NotSucpicious.pdp.exe → cmd.exe → net.exe / ipconfig.exe`.

**Network connections (Sysmon Event ID 3):**
```
index=endpoint EventCode=3
| table _time, Image, SourceIp, SourcePort, DestinationIp, DestinationPort
```
This identified the outbound connection from `NotSucpicious.pdp.exe` on `192.168.20.10` to `192.168.20.11:4444` — the C2 channel.

The connection was independently corroborated on the endpoint itself using:
```
netstat -anob
```
which showed `NotSucpicious.pdp.exe` with an `ESTABLISHED` connection to `192.168.20.11:4444`.

---

## 6. Containment

An outbound Windows Firewall rule was created to block the C2 channel:

- **Protocol:** TCP
- **Remote Port:** 4444
- **Remote IP:** 192.168.20.11
- **Action:** Block the connection
- **Profile:** Domain, Private, Public

After applying the rule, the attack was re-attempted from the Kali VM. The Meterpreter session immediately terminated (`Terminate channel 1? [y/N]` → `Meterpreter session 1 closed. Reason: Died`), confirming the outbound C2 channel was successfully blocked.

---

## 7. Eradication

The malicious process (`NotSucpicious.pdp.exe`) was terminated via Task Manager.

**Scope note:** In a production environment, eradication would also include confirming file deletion, auditing local accounts (`net user` / `net localgroup`) for unauthorized changes made during the attacker's discovery activity, and re-running detection searches to verify no further C2 traffic. These steps were considered but not carried out as part of this lab exercise; process termination was treated as sufficient to conclude the simulation.

---

## 8. Recovery

Once eradication is fully confirmed, recovery in this lab consists of:
- Restoring the Windows VM's network adapter to its normal isolated configuration (Internal Network)
- Optionally reverting to the baseline snapshot to return the environment to a clean state for future exercises

---

## 9. Lessons Learned

- **No application control or EDR blocking was in place.** The malicious file used a double-extension trick (`NotSucpicious.pdp.exe`) and executed without any preventive control stopping it. A real environment should have application whitelisting or endpoint protection capable of blocking unsigned/unknown executables from user-writable directories like Downloads.
- **The C2 channel used a well-known default port.** Port 4444 is the default Metasploit listener port. A detection rule alerting on outbound connections to this port (or other known C2 ports) from endpoints would have flagged this activity immediately rather than relying on manual investigation.
- **Manual telemetry review was time-consuming.** Building a saved search or dashboard for this exact process-chain pattern in advance would reduce investigation time in a future incident.

---

## 10. Recommendations

1. Deploy application whitelisting or an EDR solution capable of blocking execution of unsigned/suspicious executables from Downloads and other user-writable directories.
2. Create a Splunk correlation search/alert for outbound connections to known C2 ports (4444, 4443, 8080, etc.).
3. Establish a standard post-containment verification step (re-run detection searches) as part of the IR playbook to confirm containment before moving to eradication.

---

## Appendix: Supporting Screenshots

See `/screenshots` for full evidence set, including hash verification, VM/network setup, payload generation and delivery, Splunk detection queries, containment proof, and eradication.
