# Generated incident reports

## Incident 1: BruteForce at Institution_D (status: ok)
**Source:** 172.16.0.1  |  **Confidence:** 0.992  |  **Faithfulness:** 0.988

**Summary:** A brute-force attack was detected targeting Institution_D's services, resulting in a high confidence alert.

**Impact:** A brute-force attack repeatedly guesses passwords against services such as FTP and SSH, giving the attacker valid accounts and a foothold inside the network.

**MITRE:** T1110, T1110.001
- T1110 Brute Force: Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.
- T1110.001 Password Guessing: Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts.

**Response steps:**
1. Lock the targeted accounts and force a password reset
2. Block the source address temporarily
3. Review authentication logs for successful logins from that source
4. Enable multi-factor authentication on the exposed service

**Escalation:** Research computing team (ext 6400)
*Sources: bruteforce#1, bruteforce#0, T1110#0, T1110_001#0, playbook_bruteforce#0, acceptable_use#0, network_layout#0*

## Incident 2: DoS at Institution_C (status: ok)
**Source:** 172.16.0.1  |  **Confidence:** 0.966  |  **Faithfulness:** 1.0

**Summary:** A denial-of-service attack was detected targeting Institution_C, originating from IP address 172.16.0.1, with a confidence level of 0.97.

**Impact:** A denial-of-service attack exhausts the resources of a single host or application, denying legitimate users access to the service.

**MITRE:** T1499, T1499.002, T1499.003
- T1499 Endpoint Denial of Service: Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users.
- T1499.002 Service Exhaustion Flood: Adversaries may target the different network services provided by systems to conduct a denial of service (DoS).
- T1499.003 Application Exhaustion Flood: Adversaries may target resource intensive features of applications to cause a denial of service (DoS), denying availability to those applications.

**Response steps:**
1. Confirm the target service and the offending source address
2. Apply per-source rate limiting on the firewall
3. Check service health and restart if required
4. Record the incident in the ticketing system

**Escalation:** IT service desk (ext 3300)
*Sources: T1499_002#0, T1499#0, T1499_003#0, dos#0, playbook_dos#0, acceptable_use#0, network_layout#0*

## Incident 3: Botnet at Institution_B (status: ok)
**Source:** 192.168.10.15  |  **Confidence:** 0.985  |  **Faithfulness:** 1.0

**Summary:** A botnet attack was detected on Institution_B's network, originating from IP address 192.168.10.15. The attack has a high confidence level of 0.98.

**Impact:** A compromised host that contacts a command-and-control server and may take part in attacks, spam or data theft. The host is under external control and should be treated as compromised.

**MITRE:** T1071, T1071.001, T1568
- T1071 Application Layer Protocol: Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic.
- T1071.001 Web Protocols: Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic.
- T1568 Dynamic Resolution: Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations.

**Response steps:**
1. Isolate the infected host from the network
2. Block the command-and-control address at the firewall and DNS
3. Collect logs and evidence
4. Reimage the host and reset its credentials

**Escalation:** CISO office (ext 5200)
*Sources: botnet#0, T1071_001#0, T1568#0, T1071#0, playbook_botnet#0, acceptable_use#0, network_layout#0*

## Incident 4: PortScan at Institution_A (status: ok)
**Source:** 172.16.0.1  |  **Confidence:** 0.956  |  **Faithfulness:** 1.0

**Summary:** A port scan attack was detected targeting Institution_A, originating from IP address 172.16.0.1. The attack had a confidence level of 0.96.

**Impact:** Port scanning is reconnaissance: the attacker maps open ports and services to find vulnerable systems before a later attack. It rarely causes damage by itself but usually precedes exploitation or brute force.

**MITRE:** T1046, T1595.001
- T1046 Network Service Discovery: Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation.
- T1595.001 Scanning IP Blocks: Adversaries may scan victim IP blocks to gather information that can be used during targeting.

**Response steps:**
1. Temporarily block the scanning source
2. Review which ports the scan reached
3. Close any unused exposed service
4. Watch the same source for follow-up attacks for 24 hours

**Escalation:** NOC duty officer (ext 4100)
*Sources: portscan#0, T1046#0, T1595_001#0, nist_incident_response#0, playbook_portscan#0, acceptable_use#0, network_layout#0*

## Incident 5: DDoS at Institution_D (status: ok)
**Source:** 172.16.0.1  |  **Confidence:** 1.0  |  **Faithfulness:** 1.0

**Summary:** A distributed denial-of-service (DDoS) attack was detected targeting Institution_D, causing campus services to become unavailable. The attack is believed to be highly confident with a confidence level of 1.00. The source IP address is 172.16.0.1.

**Impact:** A distributed denial-of-service attack floods a network or service with traffic from many sources, saturating bandwidth or connection tables. Campus services such as the LMS, portal and DNS become unavailable.

**MITRE:** T1498, T1498.001
- T1498 Network Denial of Service: Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users.
- T1498.001 Direct Network Flood: Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target.

**Response steps:**
1. Notify the upstream provider and request traffic filtering
2. Enable SYN-flood protection and rate limits
3. Switch critical services to the backup path
4. Post a status notice for users

**Escalation:** Research computing team (ext 6400)
*Sources: T1498_001#0, ddos#0, T1498#0, nist_incident_response#0, playbook_ddos#0, acceptable_use#0, network_layout#0*

## Incident 6: BruteForce at Institution_B (status: ok)
**Source:** 172.16.0.1  |  **Confidence:** 0.992  |  **Faithfulness:** 0.988

**Summary:** A brute-force attack was detected targeting Institution_B's services, resulting in a high confidence alert. The attack aimed to guess passwords repeatedly against services such as FTP and SSH.

**Impact:** A brute-force attack repeatedly guesses passwords against services such as FTP and SSH, giving the attacker valid accounts and a foothold inside the network.

**MITRE:** T1110, T1110.001
- T1110 Brute Force: Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.
- T1110.001 Password Guessing: Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts.

**Response steps:**
1. Lock the targeted accounts and force a password reset
2. Block the source address temporarily
3. Review authentication logs for successful logins from that source
4. Enable multi-factor authentication on the exposed service

**Escalation:** CISO office (ext 5200)
*Sources: bruteforce#1, bruteforce#0, T1110#0, T1110_001#0, playbook_bruteforce#0, network_layout#0, acceptable_use#0*

## Incident 7: DoS at Institution_E (status: ok)
**Source:** 172.16.0.1  |  **Confidence:** 0.989  |  **Faithfulness:** 1.0

**Summary:** A denial-of-service attack was detected targeting Institution_E, originating from IP address 172.16.0.1. The attack has a high confidence level of 0.99.

**Impact:** A denial-of-service attack exhausts the resources of a single host or application, denying legitimate users access to the service.

**MITRE:** T1499, T1499.002, T1499.003
- T1499 Endpoint Denial of Service: Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users.
- T1499.002 Service Exhaustion Flood: Adversaries may target the different network services provided by systems to conduct a denial of service (DoS).
- T1499.003 Application Exhaustion Flood: Adversaries may target resource intensive features of applications to cause a denial of service (DoS), denying availability to those applications.

**Response steps:**
1. Confirm the target service and the offending source address
2. Apply per-source rate limiting on the firewall
3. Check service health and restart if required
4. Record the incident in the ticketing system

**Escalation:** Library systems admin (ext 7500)
*Sources: T1499_002#0, T1499#0, T1499_003#0, dos#0, playbook_dos#0, acceptable_use#0, network_layout#0*

## Incident 8: Botnet at Institution_B (status: ok)
**Source:** 192.168.10.9  |  **Confidence:** 0.985  |  **Faithfulness:** 1.0

**Summary:** A botnet attack was detected on Institution_B's network, originating from IP address 192.168.10.9. The attack has a high confidence level of 0.98.

**Impact:** A compromised host that contacts a command-and-control server and may take part in attacks, spam or data theft. The host is under external control and should be treated as compromised.

**MITRE:** T1071, T1071.001, T1568
- T1071 Application Layer Protocol: Adversaries may communicate using OSI application layer protocols to avoid detection/network filtering by blending in with existing traffic.
- T1071.001 Web Protocols: Adversaries may communicate using application layer protocols associated with web traffic to avoid detection/network filtering by blending in with existing traffic.
- T1568 Dynamic Resolution: Adversaries may dynamically establish connections to command and control infrastructure to evade common detections and remediations.

**Response steps:**
1. Isolate the infected host from the network
2. Block the command-and-control address at the firewall and DNS
3. Collect logs and evidence
4. Reimage the host and reset its credentials

**Escalation:** CISO office (ext 5200)
*Sources: botnet#0, T1071_001#0, T1568#0, T1071#0, playbook_botnet#0, acceptable_use#0, network_layout#0*

## Incident 9: PortScan at Institution_C (status: ok)
**Source:** 172.16.0.1  |  **Confidence:** 0.956  |  **Faithfulness:** 1.0

**Summary:** A port scan attack was detected targeting Institution_C, originating from IP address 172.16.0.1. The attack is likely reconnaissance, aiming to identify vulnerable systems for future exploitation.

**Impact:** Port scanning is reconnaissance: the attacker maps open ports and services to find vulnerable systems before a later attack. It rarely causes damage by itself but usually precedes exploitation or brute force.

**MITRE:** T1046, T1595.001
- T1046 Network Service Discovery: Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation.
- T1595.001 Scanning IP Blocks: Adversaries may scan victim IP blocks to gather information that can be used during targeting.

**Response steps:**
1. Temporarily block the scanning source
2. Review which ports the scan reached
3. Close any unused exposed service
4. Watch the same source for follow-up attacks for 24 hours

**Escalation:** IT service desk (ext 3300)
*Sources: portscan#0, T1046#0, T1595_001#0, nist_incident_response#0, playbook_portscan#0, acceptable_use#0, network_layout#0*

## Incident 10: DDoS at Institution_E (status: ok)
**Source:** 172.16.0.1  |  **Confidence:** 0.999  |  **Faithfulness:** 1.0

**Summary:** A Distributed Denial-of-Service (DDoS) attack was detected targeting Institution_E, impacting campus services such as the LMS, portal, and DNS.

**Impact:** A distributed denial-of-service attack floods a network or service with traffic from many sources, saturating bandwidth or connection tables. Campus services such as the LMS, portal and DNS become unavailable.

**MITRE:** T1498, T1498.001
- T1498 Network Denial of Service: Adversaries may perform Network Denial of Service (DoS) attacks to degrade or block the availability of targeted resources to users.
- T1498.001 Direct Network Flood: Adversaries may attempt to cause a denial of service (DoS) by directly sending a high-volume of network traffic to a target.

**Response steps:**
1. Notify the upstream provider and request traffic filtering
2. Enable SYN-flood protection and rate limits
3. Switch critical services to the backup path
4. Post a status notice for users

**Escalation:** Library systems admin (ext 7500)
*Sources: T1498_001#0, ddos#0, T1498#0, nist_incident_response#0, playbook_ddos#0, network_layout#0, acceptable_use#0*

## Incident 11: BruteForce at Institution_A (status: ok)
**Source:** 172.16.0.1  |  **Confidence:** 0.992  |  **Faithfulness:** 0.988

**Summary:** A brute-force attack was detected targeting Institution_A's services, resulting in a high confidence alert.

**Impact:** A brute-force attack repeatedly guesses passwords against services such as FTP and SSH, giving the attacker valid accounts and a foothold inside the network.

**MITRE:** T1110, T1110.001
- T1110 Brute Force: Adversaries may use brute force techniques to gain access to accounts when passwords are unknown or when password hashes are obtained.
- T1110.001 Password Guessing: Adversaries with no prior knowledge of legitimate credentials within the system or environment may guess passwords to attempt access to accounts.

**Response steps:**
1. Lock the targeted accounts and force a password reset
2. Block the source address temporarily
3. Review authentication logs for successful logins from that source
4. Enable multi-factor authentication on the exposed service

**Escalation:** NOC duty officer (ext 4100)
*Sources: bruteforce#1, bruteforce#0, T1110#0, T1110_001#0, playbook_bruteforce#0, acceptable_use#0, network_layout#0*

## Incident 12: DoS at Institution_B (status: ok)
**Source:** 172.16.0.1  |  **Confidence:** 0.985  |  **Faithfulness:** 1.0

**Summary:** A denial-of-service attack was detected targeting Institution_B, originating from IP address 172.16.0.1, with a confidence level of 0.98.

**Impact:** A denial-of-service attack exhausts the resources of a single host or application, denying legitimate users access to the service.

**MITRE:** T1499, T1499.002, T1499.003
- T1499 Endpoint Denial of Service: Adversaries may perform Endpoint Denial of Service (DoS) attacks to degrade or block the availability of services to users.
- T1499.002 Service Exhaustion Flood: Adversaries may target the different network services provided by systems to conduct a denial of service (DoS).
- T1499.003 Application Exhaustion Flood: Adversaries may target resource intensive features of applications to cause a denial of service (DoS), denying availability to those applications.

**Response steps:**
1. Confirm the target service and the offending source address
2. Apply per-source rate limiting on the firewall
3. Check service health and restart if required
4. Record the incident in the ticketing system

**Escalation:** CISO office (ext 5200)
*Sources: T1499_002#0, T1499#0, T1499_003#0, dos#0, playbook_dos#0, acceptable_use#0, network_layout#0*
