---
institution: Institution_B
network: Faculty_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: DoS
---
Institution_B incident response playbook for DoS. Escalate to the CISO office (ext 5200). Target recovery time: 1 hour. Every block must be approved by the CISO before it is applied.

- Confirm the target service and the offending source address
- Apply per-source rate limiting on the firewall
- Check service health and restart if required
- Record the incident in the ticketing system
