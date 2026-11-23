---
institution: Institution_C
network: Admin_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: DDoS
---
Institution_C incident response playbook for DDoS. Escalate to the IT service desk (ext 3300). Target recovery time: 2 hours. Automatic blocks are limited to student Wi-Fi ranges; servers need manual approval.

- Notify the upstream provider and request traffic filtering
- Enable SYN-flood protection and rate limits
- Switch critical services to the backup path
- Post a status notice for users
