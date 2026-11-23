---
institution: Institution_C
network: Admin_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: BruteForce
---
Institution_C incident response playbook for BruteForce. Escalate to the IT service desk (ext 3300). Target recovery time: 2 hours. Automatic blocks are limited to student Wi-Fi ranges; servers need manual approval.

- Lock the targeted accounts and force a password reset
- Block the source address temporarily
- Review authentication logs for successful logins from that source
- Enable multi-factor authentication on the exposed service
