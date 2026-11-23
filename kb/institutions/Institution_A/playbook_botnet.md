---
institution: Institution_A
network: Student_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: Botnet
---
Institution_A incident response playbook for Botnet. Escalate to the NOC duty officer (ext 4100). Target recovery time: 30 minutes. Temporary blocks of up to 1 hour may be applied automatically by the NOC.

- Isolate the infected host from the network
- Block the command-and-control address at the firewall and DNS
- Collect logs and evidence
- Reimage the host and reset its credentials
