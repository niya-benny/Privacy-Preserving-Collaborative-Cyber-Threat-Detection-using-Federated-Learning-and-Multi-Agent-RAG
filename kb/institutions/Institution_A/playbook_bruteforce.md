---
institution: Institution_A
network: Student_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: BruteForce
---
Institution_A incident response playbook for BruteForce. Escalate to the NOC duty officer (ext 4100). Target recovery time: 30 minutes. Temporary blocks of up to 1 hour may be applied automatically by the NOC.

- Lock the targeted accounts and force a password reset
- Block the source address temporarily
- Review authentication logs for successful logins from that source
- Enable multi-factor authentication on the exposed service
