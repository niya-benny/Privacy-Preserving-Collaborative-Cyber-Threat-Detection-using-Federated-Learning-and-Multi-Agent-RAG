---
institution: Institution_C
network: Admin_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: WebAttack
---
Institution_C incident response playbook for WebAttack. Escalate to the IT service desk (ext 3300). Target recovery time: 2 hours. Automatic blocks are limited to student Wi-Fi ranges; servers need manual approval.

- Enable the web application firewall rule for the detected pattern
- Review web server and database logs
- Patch or disable the vulnerable application
- Notify the data protection officer if records were exposed
