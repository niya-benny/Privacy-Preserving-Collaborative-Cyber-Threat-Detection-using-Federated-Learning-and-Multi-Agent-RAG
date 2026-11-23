---
institution: Institution_D
network: Research_Network
document_type: Security_Policy
topic: Incident_Response
attack_types: Botnet
---
Institution_D incident response playbook for Botnet. Escalate to the Research computing team (ext 6400). Target recovery time: 4 hours. Research servers are never blocked automatically; traffic is rate-limited instead.

- Isolate the infected host from the network
- Block the command-and-control address at the firewall and DNS
- Collect logs and evidence
- Reimage the host and reset its credentials
