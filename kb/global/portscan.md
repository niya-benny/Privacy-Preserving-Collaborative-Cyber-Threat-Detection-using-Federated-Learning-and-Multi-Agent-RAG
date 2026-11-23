---
institution: global
document_type: Threat_Intelligence
topic: PortScan
attack_types: PortScan
---
## Impact
Port scanning is reconnaissance: the attacker maps open ports and services to find vulnerable systems before a later attack. It rarely causes damage by itself but usually precedes exploitation or brute force.

## MITRE ATT&CK
Relevant techniques: T1046, T1595.001.

## Detection indicators
One source touching many destination ports in a short time, many short flows with few packets and SYN/RST flags.

## Mitigation guidance
Block or rate-limit the scanning source; close unused ports and services; restrict management ports to internal ranges; watch the same source for follow-up attacks.
