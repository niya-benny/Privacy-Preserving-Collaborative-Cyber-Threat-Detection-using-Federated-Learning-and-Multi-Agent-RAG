---
institution: Institution_E
network: Library_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: WebAttack
---
Institution_E incident response playbook for WebAttack. Escalate to the Library systems admin (ext 7500). Target recovery time: 1 hour. Library public terminals are blocked for 30 minutes and reimaged if compromised.

- Enable the web application firewall rule for the detected pattern
- Review web server and database logs
- Patch or disable the vulnerable application
- Notify the data protection officer if records were exposed
