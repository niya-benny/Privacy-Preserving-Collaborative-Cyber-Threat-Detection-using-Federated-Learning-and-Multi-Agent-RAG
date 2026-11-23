---
institution: Institution_D
network: Research_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: BruteForce
---
Institution_D incident response playbook for BruteForce. Escalate to the Research computing team (ext 6400). Target recovery time: 4 hours. Research servers are never blocked automatically; traffic is rate-limited instead.

- Lock the targeted accounts and force a password reset
- Block the source address temporarily
- Review authentication logs for successful logins from that source
- Enable multi-factor authentication on the exposed service
