---
institution: Institution_E
network: Library_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: PortScan
---
Institution_E incident response playbook for PortScan. Escalate to the Library systems admin (ext 7500). Target recovery time: 1 hour. Library public terminals are blocked for 30 minutes and reimaged if compromised.

- Temporarily block the scanning source
- Review which ports the scan reached
- Close any unused exposed service
- Watch the same source for follow-up attacks for 24 hours
