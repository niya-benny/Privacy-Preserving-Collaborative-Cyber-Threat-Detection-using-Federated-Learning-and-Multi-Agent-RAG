---
institution: Institution_D
network: Research_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: WebAttack
---
Institution_D incident response playbook for WebAttack. Escalate to the Research computing team (ext 6400). Target recovery time: 4 hours. Research servers are never blocked automatically; traffic is rate-limited instead.

- Enable the web application firewall rule for the detected pattern
- Review web server and database logs
- Patch or disable the vulnerable application
- Notify the data protection officer if records were exposed
