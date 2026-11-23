---
institution: Institution_B
network: Faculty_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: PortScan
---
Institution_B incident response playbook for PortScan. Escalate to the CISO office (ext 5200). Target recovery time: 1 hour. Every block must be approved by the CISO before it is applied.

- Temporarily block the scanning source
- Review which ports the scan reached
- Close any unused exposed service
- Watch the same source for follow-up attacks for 24 hours
