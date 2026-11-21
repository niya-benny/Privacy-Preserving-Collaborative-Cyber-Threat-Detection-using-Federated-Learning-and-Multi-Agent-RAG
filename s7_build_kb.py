"""STEP 7 - write the knowledge-base documents (kb/) and build the FAISS index.
GLOBAL docs: MITRE ATT&CK / CWE / CVE style summaries per CICIDS2017 attack class.
INSTITUTION docs: SYNTHETIC policies for the 5 simulated institutions -- say so in the paper.
EDIT the files in kb/ freely (they are plain markdown) and re-run this script.   Usage: python s7_build_kb.py
"""
import sys
from config import KB_DIR, INSTITUTIONS, ART
from rag.kb import KnowledgeBase

GLOBAL = {
 "DoS": dict(mitre="T1499, T1499.002, T1499.003", extra="CVE-2014-0160 (Heartbleed, OpenSSL)", impact=
  "A denial-of-service attack exhausts the resources of a single host or application (connections, CPU, memory) so legitimate users cannot reach the service. Slow-request tools such as Slowloris and Hulk keep many half-open HTTP connections alive.",
  detect="Sudden growth in connections from one source, very long flow durations with tiny payloads, high request rate to one web server.",
  mitig="Rate-limit and connection-limit per source IP; shorten connection timeouts; put a reverse proxy or WAF in front of web servers; keep OpenSSL and web servers patched."),
 "DDoS": dict(mitre="T1498, T1498.001", extra="", impact=
  "A distributed denial-of-service attack floods a network or service with traffic from many sources, saturating bandwidth or connection tables. Campus services such as the LMS, portal and DNS become unavailable.",
  detect="High packet rate to one destination, many sources with near-identical flow features, link utilisation spikes.",
  mitig="Enable upstream or ISP filtering; use rate limiting and SYN cookies; scale out or fail over critical services; blackhole the target only as a last resort."),
 "PortScan": dict(mitre="T1046, T1595.001", extra="", impact=
  "Port scanning is reconnaissance: the attacker maps open ports and services to find vulnerable systems before a later attack. It rarely causes damage by itself but usually precedes exploitation or brute force.",
  detect="One source touching many destination ports in a short time, many short flows with few packets and SYN/RST flags.",
  mitig="Block or rate-limit the scanning source; close unused ports and services; restrict management ports to internal ranges; watch the same source for follow-up attacks."),
 "BruteForce": dict(mitre="T1110, T1110.001, T1110.003", extra="CWE-307 (improper restriction of excessive authentication attempts)", impact=
  "A brute-force attack repeatedly guesses passwords against services such as FTP and SSH (tools like Patator). A success gives the attacker valid accounts and a foothold inside the network.",
  detect="Many short authentication flows from one source to port 21 or 22, repeated failed logins in service logs.",
  mitig="Lock or delay accounts after repeated failures; require key-based SSH or multi-factor authentication; use fail2ban style temporary bans; disable unused FTP; review accounts that logged in after the attack."),
 "Botnet": dict(mitre="T1071, T1071.001, T1568, T1041", extra="", impact=
  "Botnet traffic indicates a compromised host that contacts a command-and-control server and may take part in attacks, spam or data theft. The host is under external control and should be treated as compromised.",
  detect="Periodic small beacon-like flows to the same external address, unusual protocols or ports from a desktop host.",
  mitig="Isolate the host from the network; block the command-and-control address and domain at the firewall and DNS; collect evidence; reimage the machine and reset credentials used on it."),
 "WebAttack": dict(mitre="T1190", extra="CWE-89 (SQL injection), CWE-79 (cross-site scripting), CWE-307; OWASP Top 10 injection", impact=
  "Web attacks target public-facing applications with SQL injection, cross-site scripting or web login brute force. They can expose student and staff records or allow defacement of institutional portals.",
  detect="Requests with SQL keywords or script tags in parameters, many login requests to one URL, unusual HTTP error rates.",
  mitig="Place a web application firewall in front of the application; use parameterised queries and input validation; patch the application; review web server logs and database access; rate-limit login endpoints."),
 "Infiltration": dict(mitre="T1105, T1204, T1041", extra="", impact=
  "Infiltration means an attacker or malware is already inside a host, for example after a malicious download, and may scan the internal network, move laterally or exfiltrate data. It is the most serious class because the perimeter has already been bypassed.",
  detect="Unusual outbound transfers, internal scanning from a normal user host, connections to rare external addresses.",
  mitig="Isolate the host immediately; preserve memory and disk evidence; reset credentials; scan connected hosts for the same indicators; escalate to the incident response lead."),
}
NETS = ["Student_Network", "Faculty_Network", "Admin_Network", "Research_Network", "Library_Network"]
STYLE = [  # per-institution differences so the policy agent has something institution-specific to retrieve
 dict(block="Temporary blocks of up to 1 hour may be applied automatically by the NOC.", contact="NOC duty officer", ext="ext 4100", rto="30 minutes"),
 dict(block="Every block must be approved by the CISO before it is applied.", contact="CISO office", ext="ext 5200", rto="1 hour"),
 dict(block="Automatic blocks are limited to student Wi-Fi ranges; servers need manual approval.", contact="IT service desk", ext="ext 3300", rto="2 hours"),
 dict(block="Research servers are never blocked automatically; traffic is rate-limited instead.", contact="Research computing team", ext="ext 6400", rto="4 hours"),
 dict(block="Library public terminals are blocked for 30 minutes and reimaged if compromised.", contact="Library systems admin", ext="ext 7500", rto="1 hour"),
]
STEPS = {
 "DoS": ["Confirm the target service and the offending source address", "Apply per-source rate limiting on the firewall", "Check service health and restart if required", "Record the incident in the ticketing system"],
 "DDoS": ["Notify the upstream provider and request traffic filtering", "Enable SYN-flood protection and rate limits", "Switch critical services to the backup path", "Post a status notice for users"],
 "PortScan": ["Temporarily block the scanning source", "Review which ports the scan reached", "Close any unused exposed service", "Watch the same source for follow-up attacks for 24 hours"],
 "BruteForce": ["Lock the targeted accounts and force a password reset", "Block the source address temporarily", "Review authentication logs for successful logins from that source", "Enable multi-factor authentication on the exposed service"],
 "Botnet": ["Isolate the infected host from the network", "Block the command-and-control address at the firewall and DNS", "Collect logs and evidence", "Reimage the host and reset its credentials"],
 "WebAttack": ["Enable the web application firewall rule for the detected pattern", "Review web server and database logs", "Patch or disable the vulnerable application", "Notify the data protection officer if records were exposed"],
 "Infiltration": ["Isolate the host immediately", "Preserve disk and memory evidence", "Reset credentials used on the host", "Escalate to the incident response lead and scan connected hosts"],
}


def w(path, meta, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    head = "\n".join(f"{k}: {v}" for k, v in meta.items())
    path.write_text(f"---\n{head}\n---\n{body}\n", encoding="utf-8")


def main():
    for a, d in GLOBAL.items():
        body = (f"## Impact\n{d['impact']}\n\n## MITRE ATT&CK\nRelevant techniques: {d['mitre']}." + (f" Related references: {d['extra']}." if d["extra"] else "") +
                f"\n\n## Detection indicators\n{d['detect']}\n\n## Mitigation guidance\n{d['mitig']}")
        w(KB_DIR / "global" / f"{a.lower()}.md", dict(institution="global", document_type="Threat_Intelligence", topic=a, attack_types=a), body)
    w(KB_DIR / "global" / "nist_incident_response.md", dict(institution="global", document_type="Guideline", topic="Incident_Response", attack_types="ALL"),
      "Incident handling follows four phases (NIST SP 800-61): preparation; detection and analysis; containment, eradication and recovery; post-incident activity.\n\n"
      "Containment should limit damage without destroying evidence. Every incident needs a record of what was detected, what action was taken and who approved it.")
    for i, inst in enumerate(INSTITUTIONS):
        st, net = STYLE[i % len(STYLE)], NETS[i % len(NETS)]
        base = dict(institution=inst, network=net)
        w(KB_DIR / "institutions" / inst / "network_layout.md", dict(base, document_type="Network_Layout", topic="Network", attack_types="ALL"),
          f"{inst} operates the {net} segment behind a campus firewall. Critical servers (DNS, authentication, web portal) sit in a protected server zone.")
        w(KB_DIR / "institutions" / inst / "acceptable_use.md", dict(base, document_type="Security_Policy", topic="Acceptable_Use", attack_types="ALL"),
          f"{inst} acceptable-use policy: users must not run scanning or attack tools on the campus network. {st['block']}")
        for a, steps in STEPS.items():
            body = (f"{inst} incident response playbook for {a}. Escalate to the {st['contact']} ({st['ext']}). Target recovery time: {st['rto']}. {st['block']}\n\n" +
                    "\n".join(f"- {s}" for s in steps))
            w(KB_DIR / "institutions" / inst / f"playbook_{a.lower()}.md", dict(base, document_type="Security_Policy", topic="Incident_Response", attack_types=a), body)
    kb = KnowledgeBase().build(KB_DIR)
    kb.save()
    print(f"Knowledge base built: {len(kb.chunks)} chunks ({sum(c['institution'] == 'global' for c in kb.chunks)} global) -> {ART / 'kb'}")


if __name__ == "__main__":
    main()
