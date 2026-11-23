---
institution: global
document_type: Threat_Intelligence
topic: Botnet
attack_types: Botnet
---
## Impact
Botnet traffic indicates a compromised host that contacts a command-and-control server and may take part in attacks, spam or data theft. The host is under external control and should be treated as compromised.

## MITRE ATT&CK
Relevant techniques: T1071, T1071.001, T1568, T1041.

## Detection indicators
Periodic small beacon-like flows to the same external address, unusual protocols or ports from a desktop host.

## Mitigation guidance
Isolate the host from the network; block the command-and-control address and domain at the firewall and DNS; collect evidence; reimage the machine and reset credentials used on it.
