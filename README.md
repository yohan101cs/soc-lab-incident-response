# SOC Home Lab – Incident Response Simulation

A self-built home lab used to simulate a malware execution attack, generate real telemetry with Sysmon and Splunk, and carry out containment and eradication.

## Tools Used
- **VirtualBox** (Oracle VM VirtualBox)
- **Windows 10** (victim VM)
- **Kali Linux** (attacker VM)
- **Metasploit / msfvenom** (payload generation and handler)
- **Sysmon** (endpoint telemetry)
- **Splunk Enterprise** (SIEM)
- **Splunk Add-on for Sysmon** (log parsing)

## Lab Architecture
- Windows 10 VM: `192.168.20.10`
- Kali Linux VM: `192.168.20.11`
- Both VMs set to **Internal Network** in VirtualBox to isolate them from the internet and host machine
- Baseline snapshot taken on the Kali VM for recovery

## What I Did

### 1. Environment Setup
- Downloaded VirtualBox and verified the installer's integrity by checking its SHA-256 hash against Oracle's published hash list
- Created a Windows 10 VM (4GB RAM, 2 cores, 50GB disk)
- Created a Kali Linux VM
- Took a baseline snapshot of the Kali VM for recovery
- Set both VMs' network adapters to **Internal Network** to isolate the lab from the internet and host machine
- Configured static IPs (`192.168.20.10` for Windows, `192.168.20.11` for Kali) and confirmed connectivity by pinging between the two VMs

### 2. Telemetry Setup
- Installed **Splunk Enterprise** on the Windows VM as the SIEM
- Installed **Sysmon** on the Windows VM for endpoint logging
- Installed the **Splunk Add-on for Sysmon** to properly parse Sysmon event data

### 3. Attack Simulation
- Generated a Windows Meterpreter reverse TCP payload with `msfvenom`, disguised as `NotSucpicious.pdp.exe`
- Set up a Metasploit `multi/handler` listener on the Kali VM
- Served the payload from the Kali VM using a Python HTTP server and downloaded it onto the Windows VM
- Executed the payload on the Windows VM, establishing a Meterpreter session back to the Kali VM
- Ran `net user`, `net localgroup`, and `ipconfig` from the resulting shell to simulate attacker discovery activity
- Verified the established connection independently with `netstat -anob` on the Windows VM, confirming `NotSucpicious.pdp.exe` had an active connection to `192.168.20.11:4444`

### 4. Detection (Splunk)
- Queried Sysmon Event ID 1 (Process Creation) data using the process's `process_guid` to trace the full process chain:
  `NotSucpicious.pdp.exe → cmd.exe → net.exe (user / localgroup), ipconfig.exe`
- Queried Sysmon Event ID 3 (Network Connection) data and identified the outbound connection from `NotSucpicious.pdp.exe` on the Windows VM to `192.168.20.11:4444` on the Kali VM — confirming the C2 channel

### 5. Containment
- Created a Windows Defender Firewall outbound rule blocking TCP traffic on port `4444` to `192.168.20.11`
- Re-attempted the attack from the Kali VM after applying the rule — the Meterpreter session immediately closed (`Reason: Died`), confirming the firewall rule successfully blocked the C2 channel

### 6. Eradication
- Terminated the malicious process (`NotSucpicious.pdp.exe`) via Task Manager

## Repo Contents
- Screenshots of each stage above (hash verification, VM setup, network config, attack execution, Splunk queries, containment, eradication)

## Notes
This lab was built and run entirely on an internally isolated network with no internet or host-machine connectivity during the attack simulation, to safely contain the malicious payload.
