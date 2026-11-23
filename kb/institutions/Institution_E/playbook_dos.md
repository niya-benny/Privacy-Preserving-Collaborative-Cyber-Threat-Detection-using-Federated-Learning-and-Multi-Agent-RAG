---
institution: Institution_E
network: Library_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: DoS
---
Institution_E incident response playbook for DoS. Escalate to the Library systems admin (ext 7500). Target recovery time: 1 hour. Library public terminals are blocked for 30 minutes and reimaged if compromised.

- Confirm the target service and the offending source address
- Apply per-source rate limiting on the firewall
- Check service health and restart if required
- Record the incident in the ticketing system
