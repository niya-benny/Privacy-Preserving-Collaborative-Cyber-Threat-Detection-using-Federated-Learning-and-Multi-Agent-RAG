---
institution: Institution_E
network: Library_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: Botnet
---
Institution_E incident response playbook for Botnet. Escalate to the Library systems admin (ext 7500). Target recovery time: 1 hour. Library public terminals are blocked for 30 minutes and reimaged if compromised.

- Isolate the infected host from the network
- Block the command-and-control address at the firewall and DNS
- Collect logs and evidence
- Reimage the host and reset its credentials
