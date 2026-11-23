---
institution: Institution_A
network: Student_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: PortScan
---
Institution_A incident response playbook for PortScan. Escalate to the NOC duty officer (ext 4100). Target recovery time: 30 minutes. Temporary blocks of up to 1 hour may be applied automatically by the NOC.

- Temporarily block the scanning source
- Review which ports the scan reached
- Close any unused exposed service
- Watch the same source for follow-up attacks for 24 hours
