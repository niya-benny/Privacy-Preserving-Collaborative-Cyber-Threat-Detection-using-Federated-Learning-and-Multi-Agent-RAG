---
institution: Institution_E
network: Library_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: BruteForce
---
Institution_E incident response playbook for BruteForce. Escalate to the Library systems admin (ext 7500). Target recovery time: 1 hour. Library public terminals are blocked for 30 minutes and reimaged if compromised.

- Lock the targeted accounts and force a password reset
- Block the source address temporarily
- Review authentication logs for successful logins from that source
- Enable multi-factor authentication on the exposed service
