---
institution: global
document_type: Threat_Intelligence
topic: WebAttack
attack_types: WebAttack
---
## Impact
Web attacks target public-facing applications with SQL injection, cross-site scripting or web login brute force. They can expose student and staff records or allow defacement of institutional portals.

## MITRE ATT&CK
Relevant techniques: T1190. Related references: CWE-89 (SQL injection), CWE-79 (cross-site scripting), CWE-307; OWASP Top 10 injection.

## Detection indicators
Requests with SQL keywords or script tags in parameters, many login requests to one URL, unusual HTTP error rates.

## Mitigation guidance
Place a web application firewall in front of the application; use parameterised queries and input validation; patch the application; review web server logs and database access; rate-limit login endpoints.
