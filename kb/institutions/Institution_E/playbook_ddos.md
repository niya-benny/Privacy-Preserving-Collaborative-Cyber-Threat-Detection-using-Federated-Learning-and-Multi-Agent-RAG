---
institution: Institution_E
network: Library_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: DDoS
---
Institution_E incident response playbook for DDoS. Escalate to the Library systems admin (ext 7500). Target recovery time: 1 hour. Library public terminals are blocked for 30 minutes and reimaged if compromised.

- Notify the upstream provider and request traffic filtering
- Enable SYN-flood protection and rate limits
- Switch critical services to the backup path
- Post a status notice for users
