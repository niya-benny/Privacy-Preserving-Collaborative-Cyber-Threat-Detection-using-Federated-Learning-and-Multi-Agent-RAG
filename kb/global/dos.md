---
institution: global
document_type: Threat_Intelligence
topic: DoS
attack_types: DoS
---
## Impact
A denial-of-service attack exhausts the resources of a single host or application (connections, CPU, memory) so legitimate users cannot reach the service. Slow-request tools such as Slowloris and Hulk keep many half-open HTTP connections alive.

## MITRE ATT&CK
Relevant techniques: T1499, T1499.002, T1499.003. Related references: CVE-2014-0160 (Heartbleed, OpenSSL).

## Detection indicators
Sudden growth in connections from one source, very long flow durations with tiny payloads, high request rate to one web server.

## Mitigation guidance
Rate-limit and connection-limit per source IP; shorten connection timeouts; put a reverse proxy or WAF in front of web servers; keep OpenSSL and web servers patched.
