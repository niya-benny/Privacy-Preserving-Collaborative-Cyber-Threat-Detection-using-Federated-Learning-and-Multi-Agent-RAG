---
institution: Institution_A
network: Student_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: DDoS
---
Institution_A incident response playbook for DDoS. Escalate to the NOC duty officer (ext 4100). Target recovery time: 30 minutes. Temporary blocks of up to 1 hour may be applied automatically by the NOC.

- Notify the upstream provider and request traffic filtering
- Enable SYN-flood protection and rate limits
- Switch critical services to the backup path
- Post a status notice for users
