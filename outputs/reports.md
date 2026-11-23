# Generated incident reports

## Incident 1: BruteForce at Institution_D (status: ok)
**Source:** 172.16.0.1  |  **Confidence:** 0.992  |  **Faithfulness:** 0.988

**Summary:** A brute-force attack was detected targeting Institution_D's services, resulting in a high confidence alert. The attack aimed to guess passwords repeatedly against services such as FTP and SSH.

**Impact:** A brute-force attack repeatedly guesses passwords against services such as FTP and SSH, giving the attacker valid accounts and a foothold inside the network.

**MITRE:** T1110, T1110.001, T1110.003

**Response steps:**
1. Lock the targeted accounts and force a password reset
2. Block the source address temporarily
3. Review authentication logs for successful logins from that source
4. Enable multi-factor authentication on the exposed service

**Escalation:** Research computing team (ext 6400)
*Sources: bruteforce#1, bruteforce#0, nist_incident_response#0, playbook_bruteforce#0, acceptable_use#0, network_layout#0*

## Incident 2: Botnet at Institution_B (status: ok)
**Source:** 192.168.10.15  |  **Confidence:** 0.985  |  **Faithfulness:** 1.0

**Summary:** A botnet attack was detected on Institution_B's network, originating from IP address 192.168.10.15. The attack has a high confidence level of 0.98.

**Impact:** A compromised host that contacts a command-and-control server and may take part in attacks, spam or data theft.

**MITRE:** T1071, T1071.001, T1568, T1041

**Response steps:**
1. Isolate the infected host from the network
2. Block the command-and-control address at the firewall and DNS
3. Collect logs and evidence
4. Reimage the host and reset its credentials

**Escalation:** CISO office (ext 5200)
*Sources: botnet#0, nist_incident_response#0, playbook_botnet#0, acceptable_use#0, network_layout#0*

## Incident 3: BruteForce at Institution_B (status: ok)
**Source:** 172.16.0.1  |  **Confidence:** 0.992  |  **Faithfulness:** 0.988

**Summary:** A brute-force attack was detected targeting Institution_B's services, resulting in a high confidence alert.

**Impact:** A brute-force attack repeatedly guesses passwords against services such as FTP and SSH, giving the attacker valid accounts and a foothold inside the network.

**MITRE:** T1110, T1110.001, T1110.003

**Response steps:**
1. Lock the targeted accounts and force a password reset
2. Block the source address temporarily
3. Review authentication logs for successful logins from that source
4. Enable multi-factor authentication on the exposed service

**Escalation:** CISO office (ext 5200)
*Sources: bruteforce#1, bruteforce#0, nist_incident_response#0, playbook_bruteforce#0, network_layout#0, acceptable_use#0*

## Incident 4: Botnet at Institution_E (status: ok)
**Source:** 192.168.10.15  |  **Confidence:** 0.977  |  **Faithfulness:** 1.0

**Summary:** A botnet attack was detected on Institution_E's network, originating from IP address 192.168.10.15. The attack has a high confidence level of 0.98.

**Impact:** A compromised host that contacts a command-and-control server and may take part in attacks, spam or data theft.

**MITRE:** T1071, T1071.001, T1568, T1041

**Response steps:**
1. Isolate the infected host from the network
2. Block the command-and-control address at the firewall and DNS
3. Collect logs and evidence
4. Reimage the host and reset its credentials

**Escalation:** Library systems admin (ext 7500)
*Sources: botnet#0, nist_incident_response#0, playbook_botnet#0, acceptable_use#0, network_layout#0*

## Incident 5: BruteForce at Institution_A (status: ok)
**Source:** 172.16.0.1  |  **Confidence:** 0.992  |  **Faithfulness:** 0.988

**Summary:** A brute-force attack was detected targeting Institution_A's services, resulting in a high confidence alert.

**Impact:** A brute-force attack repeatedly guesses passwords against services such as FTP and SSH, giving the attacker valid accounts and a foothold inside the network.

**MITRE:** T1110, T1110.001, T1110.003

**Response steps:**
1. Lock the targeted accounts and force a password reset
2. Block the source address temporarily
3. Review authentication logs for successful logins from that source
4. Enable multi-factor authentication on the exposed service

**Escalation:** NOC duty officer (ext 4100)
*Sources: bruteforce#1, bruteforce#0, nist_incident_response#0, playbook_bruteforce#0, acceptable_use#0, network_layout#0*

## Incident 6: Botnet at Institution_B (status: ok)
**Source:** 192.168.10.9  |  **Confidence:** 0.988  |  **Faithfulness:** 1.0

**Summary:** A botnet attack was detected on Institution_B's network, originating from IP address 192.168.10.9. The attack has a high confidence level of 0.99.

**Impact:** A compromised host that contacts a command-and-control server and may take part in attacks, spam or data theft.

**MITRE:** T1071, T1071.001, T1568, T1041

**Response steps:**
1. Isolate the infected host from the network
2. Block the command-and-control address at the firewall and DNS
3. Collect logs and evidence
4. Reimage the host and reset its credentials

**Escalation:** CISO office (ext 5200)
*Sources: botnet#0, nist_incident_response#0, playbook_botnet#0, acceptable_use#0, network_layout#0*

## Incident 7: BruteForce at Institution_E (status: ok)
**Source:** 172.16.0.1  |  **Confidence:** 0.996  |  **Faithfulness:** 0.988

**Summary:** A brute-force attack was detected targeting Institution_E's services, resulting in a potential security breach.

**Impact:** A brute-force attack repeatedly guesses passwords against services such as FTP and SSH, giving the attacker valid accounts and a foothold inside the network.

**MITRE:** T1110, T1110.001, T1110.003

**Response steps:**
1. Lock the targeted accounts and force a password reset
2. Block the source address temporarily
3. Review authentication logs for successful logins from that source
4. Enable multi-factor authentication on the exposed service

**Escalation:** Library systems admin (ext 7500)
*Sources: bruteforce#1, bruteforce#0, nist_incident_response#0, playbook_bruteforce#0, acceptable_use#0, network_layout#0*

## Incident 8: Botnet at Institution_E (status: ok)
**Source:** 192.168.10.14  |  **Confidence:** 0.985  |  **Faithfulness:** 1.0

**Summary:** A botnet attack was detected on Institution_E's network, originating from IP address 192.168.10.14. The attack has a high confidence level of 0.98.

**Impact:** A compromised host that contacts a command-and-control server and may take part in attacks, spam or data theft.

**MITRE:** T1071, T1071.001, T1568, T1041

**Response steps:**
1. Isolate the infected host from the network
2. Block the command-and-control address at the firewall and DNS
3. Collect logs and evidence
4. Reimage the host and reset its credentials

**Escalation:** Library systems admin (ext 7500)
*Sources: botnet#0, nist_incident_response#0, playbook_botnet#0, acceptable_use#0, network_layout#0*

## Incident 9: BruteForce at Institution_C (status: ok)
**Source:** 172.16.0.1  |  **Confidence:** 0.994  |  **Faithfulness:** 0.988

**Summary:** A brute-force attack was detected targeting Institution_C's services, resulting in a high confidence alert.

**Impact:** A brute-force attack repeatedly guesses passwords against services such as FTP and SSH, giving the attacker valid accounts and a foothold inside the network.

**MITRE:** T1110, T1110.001, T1110.003

**Response steps:**
1. Lock the targeted accounts and force a password reset
2. Block the source address temporarily
3. Review authentication logs for successful logins from that source
4. Enable multi-factor authentication on the exposed service

**Escalation:** IT service desk (ext 3300)
*Sources: bruteforce#1, bruteforce#0, nist_incident_response#0, playbook_bruteforce#0, acceptable_use#0, network_layout#0*

## Incident 10: Botnet at Institution_B (status: ok)
**Source:** 192.168.10.14  |  **Confidence:** 0.985  |  **Faithfulness:** 1.0

**Summary:** A botnet attack was detected on Institution_B's network, originating from IP address 192.168.10.14. The attack has a high confidence level of 0.98.

**Impact:** A compromised host that contacts a command-and-control server and may take part in attacks, spam or data theft.

**MITRE:** T1071, T1071.001, T1568, T1041

**Response steps:**
1. Isolate the infected host from the network
2. Block the command-and-control address at the firewall and DNS
3. Collect logs and evidence
4. Reimage the host and reset its credentials

**Escalation:** CISO office (ext 5200)
*Sources: botnet#0, nist_incident_response#0, playbook_botnet#0, acceptable_use#0, network_layout#0*

## Incident 11: Botnet at Institution_A (status: ok)
**Source:** 192.168.10.15  |  **Confidence:** 0.985  |  **Faithfulness:** 1.0

**Summary:** A botnet attack was detected on Institution_A, originating from IP address 192.168.10.15. The attack has a high confidence level of 0.98.

**Impact:** A compromised host that contacts a command-and-control server and may take part in attacks, spam or data theft.

**MITRE:** T1071, T1071.001, T1568, T1041

**Response steps:**
1. Isolate the infected host from the network
2. Block the command-and-control address at the firewall and DNS
3. Collect logs and evidence
4. Reimage the host and reset its credentials

**Escalation:** NOC duty officer (ext 4100)
*Sources: botnet#0, nist_incident_response#0, playbook_botnet#0, acceptable_use#0, network_layout#0*

## Incident 12: Botnet at Institution_A (status: ok)
**Source:** 192.168.10.14  |  **Confidence:** 0.977  |  **Faithfulness:** 1.0

**Summary:** A botnet attack was detected on Institution_A, originating from IP address 192.168.10.14. The attack has a high confidence level of 0.98.

**Impact:** A compromised host that contacts a command-and-control server and may take part in attacks, spam or data theft.

**MITRE:** T1071, T1071.001, T1568, T1041

**Response steps:**
1. Isolate the infected host from the network
2. Block the command-and-control address at the firewall and DNS
3. Collect logs and evidence
4. Reimage the host and reset its credentials

**Escalation:** NOC duty officer (ext 4100)
*Sources: botnet#0, nist_incident_response#0, playbook_botnet#0, acceptable_use#0, network_layout#0*
