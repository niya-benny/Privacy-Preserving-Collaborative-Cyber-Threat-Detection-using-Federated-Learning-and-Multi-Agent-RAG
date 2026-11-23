---
institution: Institution_D
network: Research_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: DoS
---
Institution_D incident response playbook for DoS. Escalate to the Research computing team (ext 6400). Target recovery time: 4 hours. Research servers are never blocked automatically; traffic is rate-limited instead.

- Confirm the target service and the offending source address
- Apply per-source rate limiting on the firewall
- Check service health and restart if required
- Record the incident in the ticketing system
