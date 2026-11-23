---
institution: Institution_C
network: Admin_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: Botnet
---
Institution_C incident response playbook for Botnet. Escalate to the IT service desk (ext 3300). Target recovery time: 2 hours. Automatic blocks are limited to student Wi-Fi ranges; servers need manual approval.

- Isolate the infected host from the network
- Block the command-and-control address at the firewall and DNS
- Collect logs and evidence
- Reimage the host and reset its credentials
