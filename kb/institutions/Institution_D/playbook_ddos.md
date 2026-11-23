---
institution: Institution_D
network: Research_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: DDoS
---
Institution_D incident response playbook for DDoS. Escalate to the Research computing team (ext 6400). Target recovery time: 4 hours. Research servers are never blocked automatically; traffic is rate-limited instead.

- Notify the upstream provider and request traffic filtering
- Enable SYN-flood protection and rate limits
- Switch critical services to the backup path
- Post a status notice for users
