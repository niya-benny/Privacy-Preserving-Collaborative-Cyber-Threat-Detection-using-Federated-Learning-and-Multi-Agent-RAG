---
institution: Institution_B
network: Faculty_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: Botnet
---
Institution_B incident response playbook for Botnet. Escalate to the CISO office (ext 5200). Target recovery time: 1 hour. Every block must be approved by the CISO before it is applied.

- Isolate the infected host from the network
- Block the command-and-control address at the firewall and DNS
- Collect logs and evidence
- Reimage the host and reset its credentials
