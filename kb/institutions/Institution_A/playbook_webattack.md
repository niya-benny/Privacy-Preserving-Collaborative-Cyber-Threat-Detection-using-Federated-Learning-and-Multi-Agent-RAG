---
institution: Institution_A
network: Student_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: WebAttack
---
Institution_A incident response playbook for WebAttack. Escalate to the NOC duty officer (ext 4100). Target recovery time: 30 minutes. Temporary blocks of up to 1 hour may be applied automatically by the NOC.

- Enable the web application firewall rule for the detected pattern
- Review web server and database logs
- Patch or disable the vulnerable application
- Notify the data protection officer if records were exposed
