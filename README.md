# Splunk Detection Queries (SPL)

A library of Splunk Search Processing Language (SPL) queries for detecting common attack techniques, each mapped to a MITRE ATT&CK technique ID.

## Queries

### T1110 – Brute Force
```spl
index=security sourcetype=WinEventLog:Security EventCode=4625
| stats count by src_ip, dest, Account_Name
| where count > 10
| sort -count
```
Flags accounts/hosts with more than 10 failed logons — tune threshold to your environment's baseline.

### T1078 – Valid Accounts (Impossible Travel)
```spl
index=security sourcetype=WinEventLog:Security EventCode=4624
| iplocation src_ip
| stats earliest(_time) as first_seen, latest(_time) as last_seen, values(Country) as countries by Account_Name
| where mvcount(countries) > 1
```
Detects a single account authenticating from multiple countries within a short window.

### T1059.001 – Malicious PowerShell
```spl
index=security sourcetype="WinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
| search ScriptBlockText="*-EncodedCommand*" OR ScriptBlockText="*IEX*" OR ScriptBlockText="*DownloadString*"
| table _time, Computer, User, ScriptBlockText
```
Surfaces encoded or download-cradle-style PowerShell execution.

### T1548.002 – Privilege Escalation (New Admin Group Member)
```spl
index=security sourcetype=WinEventLog:Security EventCode=4732
| table _time, Group_Name, Member_Name, Caller_User_Name
```
Tracks additions to privileged local/domain groups.

### T1046 – Network Service Scanning (Nmap-style)
```spl
index=network sourcetype=firewall
| stats dc(dest_port) as unique_ports by src_ip, dest_ip
| where unique_ports > 20
```
Flags a single source hitting many destination ports on one host — classic port scan signature.

## Notes
- Field names assume standard Splunk CIM (Common Information Model) mappings — adjust to your own source types.
- Thresholds are starting points, not production-ready values. Every environment's baseline is different.

## Related
See [`04-MITRE-ATTACK-Detection-Mapping`](../04-MITRE-ATTACK-Detection-Mapping) for the broader technique-to-detection reference these queries are drawn from.
