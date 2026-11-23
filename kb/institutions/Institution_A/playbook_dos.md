---
institution: Institution_A
network: Student_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: DoS
---
Institution_A incident response playbook for DoS. Escalate to the NOC duty officer (ext 4100). Target recovery time: 30 minutes. Temporary blocks of up to 1 hour may be applied automatically by the NOC.

- Confirm the target service and the offending source address
- Apply per-source rate limiting on the firewall
- Check service health and restart if required
- Record the incident in the ticketing system
