---
institution: Institution_D
network: Research_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: Infiltration
---
Institution_D incident response playbook for Infiltration. Escalate to the Research computing team (ext 6400). Target recovery time: 4 hours. Research servers are never blocked automatically; traffic is rate-limited instead.

- Isolate the host immediately
- Preserve disk and memory evidence
- Reset credentials used on the host
- Escalate to the incident response lead and scan connected hosts
