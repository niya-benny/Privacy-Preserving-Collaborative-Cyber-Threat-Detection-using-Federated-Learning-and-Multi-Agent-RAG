---
institution: Institution_B
network: Faculty_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: BruteForce
---
Institution_B incident response playbook for BruteForce. Escalate to the CISO office (ext 5200). Target recovery time: 1 hour. Every block must be approved by the CISO before it is applied.

- Lock the targeted accounts and force a password reset
- Block the source address temporarily
- Review authentication logs for successful logins from that source
- Enable multi-factor authentication on the exposed service
