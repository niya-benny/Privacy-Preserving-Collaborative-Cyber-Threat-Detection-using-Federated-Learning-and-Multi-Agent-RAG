---
institution: Institution_E
network: Library_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: Infiltration
---
Institution_E incident response playbook for Infiltration. Escalate to the Library systems admin (ext 7500). Target recovery time: 1 hour. Library public terminals are blocked for 30 minutes and reimaged if compromised.

- Isolate the host immediately
- Preserve disk and memory evidence
- Reset credentials used on the host
- Escalate to the incident response lead and scan connected hosts
