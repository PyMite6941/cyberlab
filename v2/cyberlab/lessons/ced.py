"""The parts of the AP Cybersecurity course framework the labs connect to.

Codes are the framework's own essential-knowledge codes (unit.topic.objective.
statement, e.g. 5.1.B.4). The text beside each code is our short summary of
that statement, not the College Board's wording; read the framework itself
for the exact text.

Source: AP Cybersecurity Course and Exam Description, effective Fall 2026
(College Board). AP is a trademark registered by the College Board, which is
not affiliated with, and does not endorse, this project.
"""

from __future__ import annotations

CED_SOURCE = "AP Cybersecurity Course and Exam Description (College Board, effective Fall 2026)"
CED_URL = "https://apcentral.collegeboard.org/courses/ap-cybersecurity"

UNITS = {
    "1": "Introduction to Security",
    "2": "Securing Spaces",
    "3": "Securing Networks",
    "4": "Securing Devices",
    "5": "Securing Applications and Data",
}

CED = {
    # Unit 1: Introduction to Security
    "1.2.A.1": "Online password attacks try common passwords, common patterns or stolen "
               "passwords against a live login.",
    "1.2.A.2": "Signs of an online password attack: many failed logins in a short time, and "
               "logins at unusual times or from unknown devices.",
    "1.2.B.2": "Adversaries build a dictionary of likely passwords and use an automated tool "
               "to submit them.",
    "1.2.C.1": "Strong passwords are long, random and unique; a password manager or a long "
               "passphrase helps.",
    "1.2.C.3": "Multifactor authentication (MFA) adds extra proof of identity on top of the password.",
    "1.3.B.1": "An adversary who captures network traffic cannot read what was sent over an "
               "encrypted protocol such as HTTPS.",
    # Unit 2: Securing Spaces
    "2.1.C.2": "Reconnaissance: adversaries gather as much information about a target as they can.",
    "2.1.C.5": "Lateral movement: adversaries escalate privileges by reaching accounts with "
               "elevated permissions.",
    "2.1.C.6": "Taking action: adversaries collect targeted data and exfiltrate it.",
    # Unit 3: Securing Networks
    "3.1.A.2": "Eavesdropping (sniffing) is capturing data in transit so it can be recorded and copied.",
    "3.1.A.4": "A smurf attack sends ICMP requests carrying the victim's address to a network's "
               "broadcast address, so every device replies to the victim: a denial of service (DoS).",
    "3.1.B.1": "Adversaries send malicious traffic to flood a network, to map its internal "
               "structure, or to spoof a device; missing or misconfigured firewalls leave it exposed.",
    "3.5.A.2": "A network intrusion detection system (NIDS) analyzes traffic and raises an alert "
               "when it detects malicious activity.",
    "3.5.A.4": "A SIEM collects and analyzes data from many sources to find patterns that may "
               "indicate an attack.",
    "3.5.E.6": "Smurf attacks are detected by watching for a sudden increase in ICMP requests "
               "sent to the broadcast address.",
    "3.5.E.7": "Network-based indicators of compromise are found in packet captures (addresses, "
               "ports, protocols): unauthorized scans, unusual traffic spikes, mismatched "
               "port and application traffic.",
    # Unit 4: Securing Devices
    "4.2.A.4": "MD5 and SHA-1 are deprecated hash functions.",
    "4.2.A.5": "Services should store a hash of each password, never the plaintext.",
    "4.2.A.6": "A unique random salt is hashed with each password, so identical passwords get "
               "different hashes.",
    "4.2.B.2": "Online attacks try passwords against a live login; offline attacks run against a "
               "captured hash database and so bypass account lockout.",
    "4.2.B.4": "Many users pick easy-to-guess passwords, and adversaries try the common ones.",
    "4.2.B.6": "Offline attacks hash candidate passwords and compare them to a captured hash: "
               "brute force tries every possibility, a dictionary attack tries a list of common passwords.",
    "4.2.B.7": "A rainbow table is a precomputed table of passwords and their hashes.",
    "4.2.C.6": "MFA uses more than one authentication factor and is more secure than a single factor.",
    "4.2.D.5": "An account lockout after a few invalid logins stops an adversary from guessing "
               "passwords continuously.",
    "4.4.A.6": "Behavior-based indicators in authentication and access logs: repeated failed "
               "logins, unusual login times or places, unauthorized attempts to reach sensitive "
               "data, attempts to elevate privileges.",
    "4.4.D.1": "Online password attacks show up in authentication logs as one user or source "
               "trying many wrong passwords.",
    # Unit 5: Securing Applications and Data
    "5.1.A.2": "Administrative users can control the whole system, so an account with admin "
               "privileges it doesn't need is a bigger prize for an adversary.",
    "5.1.A.3": "Weak access control settings let adversaries read or change data they should "
               "not be able to reach.",
    "5.1.B.2": "Data validation checks that input matches what is expected; applications that "
               "skip it are open to injection-type attacks.",
    "5.1.B.3": "SQL is the language applications use to query databases; building queries from "
               "unvalidated or unsanitized input makes an application vulnerable.",
    "5.1.B.4": "A SQL injection puts SQL commands and control characters into an input field, "
               "breaching confidentiality (returning too much) or integrity (changing data).",
    "5.1.B.5": "JavaScript runs in the visitor's browser and can reach sensitive data stored there.",
    "5.1.B.6": "Cross-site scripting (XSS) injects code that the victim's browser runs: reflected "
               "(Type I, carried in a link) or stored (Type II, saved on the site, e.g. a comment).",
    "5.2.C.7": "Least privilege: give each entity exactly the access it needs and no more.",
    "5.2.D.1": "Authorization is granting an entity a specific type of access to a resource; "
               "access controls enforce it.",
    "5.5.B.1": "Applications wrap user input in control characters such as the single quote, "
               "double quote and semicolon.",
    "5.5.B.2": "Input sanitization checks or cleans user input before it is used, protecting "
               "against SQL injection, XSS and directory traversal.",
    "5.6.E.1": "SQL injection is detected by reviewing logged user input for quotes, boolean "
               "conditions such as OR 1=1, the -- comment marker and SQL keywords.",
    "5.6.E.2": "XSS is detected by reviewing user input for suspicious tags, especially <script>.",
}
