---
institution: global
document_type: Threat_Intelligence
topic: BruteForce
attack_types: BruteForce
---
## Impact
A brute-force attack repeatedly guesses passwords against services such as FTP and SSH (tools like Patator). A success gives the attacker valid accounts and a foothold inside the network.

## MITRE ATT&CK
Relevant techniques: T1110, T1110.001, T1110.003. Related references: CWE-307 (improper restriction of excessive authentication attempts).

## Detection indicators
Many short authentication flows from one source to port 21 or 22, repeated failed logins in service logs.

## Mitigation guidance
Lock or delay accounts after repeated failures; require key-based SSH or multi-factor authentication; use fail2ban style temporary bans; disable unused FTP; review accounts that logged in after the attack.
