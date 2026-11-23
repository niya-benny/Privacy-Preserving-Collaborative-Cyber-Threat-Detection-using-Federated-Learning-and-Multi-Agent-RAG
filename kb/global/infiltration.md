---
institution: global
document_type: Threat_Intelligence
topic: Infiltration
attack_types: Infiltration
---
## Impact
Infiltration means an attacker or malware is already inside a host, for example after a malicious download, and may scan the internal network, move laterally or exfiltrate data. It is the most serious class because the perimeter has already been bypassed.

## MITRE ATT&CK
Relevant techniques: T1105, T1204, T1041.

## Detection indicators
Unusual outbound transfers, internal scanning from a normal user host, connections to rare external addresses.

## Mitigation guidance
Isolate the host immediately; preserve memory and disk evidence; reset credentials; scan connected hosts for the same indicators; escalate to the incident response lead.
