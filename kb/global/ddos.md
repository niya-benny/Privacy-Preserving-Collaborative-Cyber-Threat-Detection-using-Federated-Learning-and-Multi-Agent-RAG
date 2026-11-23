---
institution: global
document_type: Threat_Intelligence
topic: DDoS
attack_types: DDoS
---
## Impact
A distributed denial-of-service attack floods a network or service with traffic from many sources, saturating bandwidth or connection tables. Campus services such as the LMS, portal and DNS become unavailable.

## MITRE ATT&CK
Relevant techniques: T1498, T1498.001.

## Detection indicators
High packet rate to one destination, many sources with near-identical flow features, link utilisation spikes.

## Mitigation guidance
Enable upstream or ISP filtering; use rate limiting and SYN cookies; scale out or fail over critical services; blackhole the target only as a last resort.
