---
institution: Institution_D
network: Research_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: PortScan
---
Institution_D incident response playbook for PortScan. Escalate to the Research computing team (ext 6400). Target recovery time: 4 hours. Research servers are never blocked automatically; traffic is rate-limited instead.

- Temporarily block the scanning source
- Review which ports the scan reached
- Close any unused exposed service
- Watch the same source for follow-up attacks for 24 hours
