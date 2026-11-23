---
institution: Institution_C
network: Admin_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: PortScan
---
Institution_C incident response playbook for PortScan. Escalate to the IT service desk (ext 3300). Target recovery time: 2 hours. Automatic blocks are limited to student Wi-Fi ranges; servers need manual approval.

- Temporarily block the scanning source
- Review which ports the scan reached
- Close any unused exposed service
- Watch the same source for follow-up attacks for 24 hours
