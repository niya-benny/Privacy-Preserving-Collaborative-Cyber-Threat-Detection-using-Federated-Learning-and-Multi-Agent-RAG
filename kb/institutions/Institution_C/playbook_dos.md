---
institution: Institution_C
network: Admin_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: DoS
---
Institution_C incident response playbook for DoS. Escalate to the IT service desk (ext 3300). Target recovery time: 2 hours. Automatic blocks are limited to student Wi-Fi ranges; servers need manual approval.

- Confirm the target service and the offending source address
- Apply per-source rate limiting on the firewall
- Check service health and restart if required
- Record the incident in the ticketing system
