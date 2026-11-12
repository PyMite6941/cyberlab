"""Debriefs for the network track (packet captures and scanning)."""

from __future__ import annotations

from cyberlab.lessons import Bullets, Code, Lesson, register

WIRESHARK_GUIDE = ("Wireshark User's Guide", "https://www.wireshark.org/docs/wsug_html_chunked/")
WIRESHARK_FILTERS = ("Wireshark display filter reference",
                     "https://www.wireshark.org/docs/dfref/")

register(Lesson(
    id="net-http-creds",
    title="Passwords in cleartext HTTP",
    summary=("You read alice's password straight out of a packet capture. Nobody broke "
             "any encryption, because there was none: HTTP sends everything as readable text."),
    attacked=[
        "The weak link is the connection between alice's browser and the server. The "
        "login form was submitted over HTTP, so the request crossed the network exactly "
        "as the browser wrote it:",
        Code("""
POST /login HTTP/1.1
Host: intranet.local
Content-Type: application/x-www-form-urlencoded

username=alice&password=«N0rth-........»
""", "What is inside the TCP segment, byte for byte"),
        "Anyone positioned on the path can copy those bytes: someone on the same Wi-Fi, "
        "a compromised router, or an attacker who has redirected traffic through their "
        "own machine (an on-path attack).",
    ],
    how=[
        Bullets([
            "A capture tool (Wireshark, tshark, tcpdump) records every frame the network "
            "interface sees.",
            "The display filter  http.request.method == \"POST\"  narrows hundreds of "
            "packets to the form submissions.",
            "Follow > TCP Stream (or HTTP Stream) reassembles the conversation in order, "
            "and the form body is right there.",
        ]),
        Code("""
tshark -r capture.pcap -Y 'http.request.method == "POST"' -T fields -e urlencoded-form.key -e urlencoded-form.value
""", "The same thing on the command line"),
        "The capture also shows the layers doing their jobs: Ethernet carries IP, IP "
        "carries TCP, a three-way handshake (SYN, SYN-ACK, ACK) opens the connection, and "
        "HTTP rides on top. None of those layers provides secrecy.",
    ],
    why=[
        "HTTP has no encryption. It was designed for sharing documents, and "
        "confidentiality was added later as a separate layer (TLS). A site that accepts "
        "logins over plain HTTP exposes every password to everyone on the path.",
    ],
    defend=[
        Bullets([
            "HTTPS everywhere: HTTP inside TLS. The same capture would show only the "
            "handshake and encrypted application data. An eavesdropper learns which "
            "server was contacted, not what was said.",
            "Redirect HTTP to HTTPS and send the HSTS header, which makes browsers "
            "refuse plain HTTP for that site in future.",
            "Browsers now warn on password fields served over HTTP, and free "
            "certificates (Let's Encrypt) removed the cost excuse.",
            "MFA limits the damage if a password is captured anyway.",
            "On untrusted networks, a VPN encrypts the traffic of applications that do "
            "not protect themselves.",
        ]),
    ],
    detect=[
        "Defenders run the same analysis you did, on purpose: capture traffic at the "
        "network edge and look for credentials or other sensitive data in cleartext "
        "protocols (HTTP, FTP, Telnet). Any hit is a finding to fix. Useful filters:",
        Code("""
http.request.method == "POST"
frame contains "password"
ftp.request.command == "PASS"
"""),
    ],
    ced=["3.1.A.2", "1.3.B.1", "3.5.E.7"],
    links=[
        WIRESHARK_GUIDE,
        ("Wireshark wiki: following TCP streams",
         "https://www.wireshark.org/docs/wsug_html_chunked/ChAdvFollowStreamSection.html"),
        ("Cloudflare Learning Center: why use HTTPS?",
         "https://www.cloudflare.com/learning/ssl/why-use-https/"),
        ("MDN: Strict-Transport-Security (HSTS)",
         "https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security"),
    ],
))

register(Lesson(
    id="net-port-scan",
    title="Port scanning",
    summary=("You picked the scanner out of normal traffic: one address sending SYN "
             "packets to many different ports in a fraction of a second."),
    attacked=[
        "A port scan attacks nothing by itself. It is reconnaissance: the scanner asks "
        "every port on the server 'is anything listening here?' to build a list of "
        "services worth attacking. What it exploits is the TCP handshake, which answers "
        "that question honestly to anyone who asks.",
    ],
    how=[
        Code("""
scanner -> server   SYN                 "I'd like to connect to port N"
server  -> scanner  SYN, ACK            port N is OPEN (something is listening)
server  -> scanner  RST, ACK            port N is CLOSED
(no answer at all)                      port N is FILTERED by a firewall
""", "What each reply tells the scanner"),
        Bullets([
            "A SYN scan (nmap -sS) sends only the first packet of the handshake to each "
            "port and never completes the connection, which is fast and leaves less in "
            "application logs.",
            "In the capture, normal clients send a few SYNs to the ports of real services "
            "(22, 80, 443). The scanner sends SYNs to dozens of unrelated ports, "
            "milliseconds apart.",
            "The follow-up is service detection (nmap -sV): connect to each open port and "
            "identify the software and version, then look up known vulnerabilities.",
        ]),
        Code("""
tshark -r capture.pcap -Y 'tcp.flags.syn==1 && tcp.flags.ack==0' -T fields -e ip.src | sort | uniq -c | sort -rn
""", "Count connection attempts per source"),
    ],
    why=[
        "Every open port is a service reachable by whoever can send it a packet. The "
        "server answered the scanner because nothing between them decided the scanner "
        "should not be asking.",
    ],
    defend=[
        Bullets([
            "A firewall with a default-deny rule: only the ports that must be public are "
            "reachable, and everything else is silently dropped (the scanner sees "
            "'filtered', and learns nothing).",
            "Turn off services that are not needed. A closed port cannot be exploited.",
            "Keep the exposed services patched, since those are what the scan finds.",
            "Network segmentation, so a scanner inside one segment cannot see the rest.",
            "Intrusion detection and prevention systems recognize scan patterns and can "
            "block the source automatically.",
        ]),
        "Scanning your own network is also a defensive routine: administrators run nmap "
        "regularly to find services that should not be exposed before someone else does. "
        "Only scan systems you own or have written permission to test.",
    ],
    detect=[
        "The signature is one source, many destination ports, short time, mostly "
        "unanswered or reset connections. Firewalls and IDS tools alert on exactly that "
        "ratio. In Wireshark, Statistics > Conversations sorted by packet count shows it "
        "at a glance.",
    ],
    ced=["2.1.C.2", "3.1.B.1", "3.5.A.2", "3.5.E.7"],
    links=[
        ("Nmap Reference Guide: port scanning techniques",
         "https://nmap.org/book/man-port-scanning-techniques.html"),
        ("Nmap Network Scanning: port scanning basics",
         "https://nmap.org/book/man-port-scanning-basics.html"),
        WIRESHARK_FILTERS,
    ],
))

register(Lesson(
    id="net-nmap",
    title="Finding a hidden service with nmap",
    summary=("You found a service nobody told you about by asking every port on the "
             "machine, then connected to it and read what it said."),
    attacked=[
        "The weak link is an assumption: that a service on an unusual port is hidden. "
        "The backup service listens on a high, unadvertised port and needs no login, "
        "relying on nobody knowing it is there.",
    ],
    how=[
        Code("""
nmap -p- 127.0.0.1                     # every TCP port, 1 to 65535
nmap -sV -p <port> 127.0.0.1           # ask the service what it is
nc 127.0.0.1 <port>                    # connect and read its banner
""", "The three steps"),
        Bullets([
            "By default nmap checks only the 1,000 most common ports. -p- makes it check "
            "all 65,535, which takes seconds on a local machine.",
            "Each probe is the start of a TCP handshake. A SYN-ACK reply means open, a "
            "RST means closed.",
            "Many services announce themselves as soon as you connect (a banner): "
            "software name, version, sometimes far too much. nmap -sV reads banners and "
            "matches them against a database of known services.",
        ]),
    ],
    why=[
        "Security through obscurity: the only protection was that the port number was "
        "not published. Port numbers are not secrets. There are only 65,535 of them and "
        "a scanner tries them all.",
    ],
    defend=[
        Bullets([
            "Require authentication on every service, however obscure its address.",
            "Bind internal services to the interface that needs them (this lab binds to "
            "127.0.0.1, so only this machine can reach it), and firewall the rest.",
            "Remove version details and internal data from banners.",
            "Keep an inventory: scan your own machines on a schedule and investigate any "
            "listening port that is not on the list.",
        ]),
        Code("""
ss -tlnp        # which programs are listening on which TCP ports (Linux)
""", "The defender's view of the same question, from inside the machine"),
    ],
    detect=[
        "A full port scan is thousands of connection attempts from one source in "
        "seconds, almost all refused. See the net-port-scan debrief for what that looks "
        "like in a packet capture.",
    ],
    ced=["2.1.C.2", "3.1.B.1", "3.5.E.7"],
    links=[
        ("Nmap Reference Guide", "https://nmap.org/book/man.html"),
        ("Nmap: service and version detection",
         "https://nmap.org/book/man-version-detection.html"),
        ("scanme.nmap.org: a host the Nmap project lets you scan for practice",
         "http://scanme.nmap.org/"),
    ],
))

register(Lesson(
    id="net-dns-tunnel",
    title="DNS tunneling",
    summary=("You found data being smuggled out of the network disguised as DNS lookups: "
             "a stream of long, random-looking names that all end in the same domain."),
    attacked=[
        "The weak link is the network's trust in DNS. Almost every network lets DNS "
        "queries out, because nothing works without name resolution, and few look at "
        "what the queries contain.",
    ],
    how=[
        Bullets([
            "The attacker registers a domain and runs its authoritative name server.",
            "Malware on the inside host chops the stolen data into pieces, encodes each "
            "piece as text, and looks up a name built from it:",
        ]),
        Code("«3f9a1c0b77e2d4a8...».x1234abc.net   TXT ?",
             "One query; the highlighted label is 32 characters of encoded data"),
        Bullets([
            "The company's own resolver does not know that name, so it forwards the "
            "query across the internet to the attacker's name server, exactly as DNS is "
            "designed to do. The data has now left the network inside a legitimate "
            "DNS request.",
            "Replies (often TXT records, which can hold arbitrary text) carry commands "
            "back in. It is slow, but it passes through firewalls that block everything else.",
        ]),
        Code("""
tshark -r capture.pcap -Y 'dns.qry.type == 16' -T fields -e dns.qry.name
""", "List the names of the TXT queries"),
    ],
    why=[
        "Outbound DNS was allowed without inspection. The firewall rule says 'DNS is "
        "fine', and the tunnel is, technically, valid DNS.",
    ],
    defend=[
        Bullets([
            "Force all clients to use the organization's resolver and block direct DNS "
            "to the internet, so every query passes one inspection point.",
            "DNS filtering and monitoring on that resolver: block newly registered and "
            "known-bad domains, and alert on tunneling patterns.",
            "Endpoint protection to catch the malware making the queries.",
            "Data loss prevention and least privilege, so the compromised host has less "
            "worth stealing.",
        ]),
    ],
    detect=[
        "Normal lookups are short and repeat a few familiar names. Tunnels look different:",
        Bullets([
            "Very long labels (DNS allows up to 63 characters; real hostnames rarely "
            "come close).",
            "High-entropy, random-looking subdomains that never repeat.",
            "Many queries to one otherwise unknown domain from a single host.",
            "Unusual record types in bulk, especially TXT and NULL.",
        ]),
        Code("""
dns.qry.name.len > 40
dns.qry.type == 16
""", "Wireshark display filters that surface it"),
    ],
    ced=["2.1.C.6", "3.5.A.4", "3.5.E.7"],
    links=[
        ("Cloudflare Learning Center: what is DNS tunneling?",
         "https://www.cloudflare.com/learning/dns/dns-tunneling/"),
        ("MITRE ATT&CK T1071.004: Application Layer Protocol: DNS",
         "https://attack.mitre.org/techniques/T1071/004/"),
        WIRESHARK_FILTERS,
    ],
))

_SMURF_HOW = [
    Code("""
attacker -> 198.51.100.255 (broadcast)   ICMP echo request, source = «victim»   (forged)
every host on 198.51.100.0/24 -> «victim»   ICMP echo reply
""", "One forged packet in, one reply per host out"),
    Bullets([
        "Ping is ICMP echo: a type 8 request is answered with a type 0 reply, sent to "
        "whatever source address the request carried.",
        "The attacker forges (spoofs) the source address, putting the victim's address "
        "there. IP has no built-in way to verify a source address.",
        "The request is sent to the network's broadcast address, so every host on that "
        "network receives it and each one replies, to the victim.",
        "The hosts that reply are reflectors: they are not compromised, they are just "
        "answering a ping. The victim receives a flood from many real addresses and "
        "never sees the attacker's.",
        "Amplification factor = replies received per request sent. With 12 reflectors, "
        "each packet the attacker sends costs the victim 12.",
    ]),
]
_SMURF_WHY = [
    "Two design weaknesses combined: source addresses can be forged, and networks used "
    "to accept pings addressed to their broadcast address from outside.",
]
_SMURF_DEFEND = [
    Bullets([
        "Routers no longer forward directed broadcasts. This has been the required "
        "default since RFC 2644 (1999), which is why classic smurf attacks are rare today.",
        "Hosts ignore pings sent to a broadcast address (the Linux default).",
        "Ingress filtering (BCP 38): internet providers drop packets whose source "
        "address could not have come from that customer, which stops spoofing at the source.",
        "Rate-limit ICMP at the network edge, and use a DDoS mitigation service that "
        "absorbs floods upstream.",
    ]),
    "The idea did not die, it moved. Modern reflection attacks use the same two "
    "ingredients (a forged source and a service that answers with more than it was "
    "sent) over DNS, NTP and memcached, with far larger amplification.",
]
_SMURF_DETECT = [
    "Look for ICMP echo requests addressed to a broadcast address, followed by a burst "
    "of echo replies from many sources to one destination that never sent a request to them:",
    Code("""
icmp.type == 8 && ip.dst == 198.51.100.255        the forged requests
icmp.type == 0                                    the flood of replies
""", "Wireshark display filters"),
    "Counting distinct reply sources tells you the number of reflectors, not the number "
    "of attackers. One attacker forged every request.",
]
_SMURF_LINKS = [
    ("Cloudflare Learning Center: smurf DDoS attack",
     "https://www.cloudflare.com/learning/ddos/smurf-ddos-attack/"),
    ("RFC 2644: Changing the Default for Directed Broadcasts in Routers",
     "https://www.rfc-editor.org/rfc/rfc2644"),
    ("RFC 2827 (BCP 38): Network Ingress Filtering",
     "https://www.rfc-editor.org/rfc/rfc2827"),
]

register(Lesson(
    id="net-icmp-echo",
    title="ICMP echo (ping)",
    summary=("You read a ping sweep in a capture and found the one host that answered. "
             "This is the building block the smurf challenges turn into an attack."),
    attacked=[
        "Nothing was attacked here. You observed ICMP echo, the protocol behind ping, "
        "doing what it is for: testing whether a host is reachable.",
    ],
    how=[
        Code("""
192.0.2.10 -> 198.51.100.22   ICMP type 8 (echo request)  id=0x1a2b seq=3
198.51.100.22 -> 192.0.2.10   ICMP type 0 (echo reply)    id=0x1a2b seq=3
""", "A request and its reply share the same id and sequence number"),
        Bullets([
            "ICMP sits directly on IP. It has no ports; messages are identified by a "
            "type and a code.",
            "A host that is up (and allowed to) answers each echo request with an echo "
            "reply. A request with no reply means the host is down, or a firewall "
            "dropped the packet.",
            "Sending requests to a whole range of addresses is a ping sweep, the "
            "quickest way to find which hosts exist (nmap -sn does this).",
        ]),
    ],
    why=[
        "Ping is useful, so it is widely allowed. The same replies that help an "
        "administrator troubleshoot also tell an attacker which addresses are worth "
        "scanning next.",
    ],
    defend=[
        Bullets([
            "Firewalls commonly drop echo requests arriving from the internet while "
            "allowing ping inside the network.",
            "Rate-limit ICMP so it cannot be used to flood.",
            "Do not rely on hiding from ping: a host with any open port is still found "
            "by a port scan.",
        ]),
    ],
    detect=[
        "A ping sweep is one source sending echo requests to many addresses in "
        "sequence. Filter with  icmp.type == 8  and look at the destination column.",
    ],
    ced=["3.1.A.4", "3.5.E.7"],
    links=[
        ("Cloudflare Learning Center: what is ICMP?",
         "https://www.cloudflare.com/learning/ddos/glossary/internet-control-message-protocol-icmp/"),
        ("Nmap: host discovery (ping scanning)", "https://nmap.org/book/man-host-discovery.html"),
    ],
))

register(Lesson(
    id="net-smurf-victim",
    title="Smurf attack: finding the victim",
    summary=("You identified the victim of a smurf attack: the address that dozens of "
             "echo replies pour into, although it never asked for them."),
    attacked=[
        "The target is the victim's availability: its network link and its ability to "
        "process packets. The attack abuses ICMP echo and the broadcast address of a "
        "third-party network to do the flooding.",
    ],
    how=_SMURF_HOW,
    why=_SMURF_WHY,
    defend=_SMURF_DEFEND,
    detect=_SMURF_DETECT,
    ced=["3.1.A.4", "3.1.B.1", "3.5.E.6", "3.5.E.7"],
    links=_SMURF_LINKS,
))

register(Lesson(
    id="net-smurf-amp",
    title="Smurf attack: measuring amplification",
    summary=("You counted the reflectors in a smurf attack, which is the attack's "
             "amplification factor: how many packets hit the victim for each one the "
             "attacker sends."),
    attacked=[
        "The same target as before, the victim's availability. This time you measured "
        "what makes the attack cheap for the attacker and expensive for the victim.",
    ],
    how=_SMURF_HOW,
    why=_SMURF_WHY,
    defend=_SMURF_DEFEND,
    detect=_SMURF_DETECT,
    ced=["3.1.A.4", "3.1.B.1", "3.5.E.6", "3.5.E.7"],
    links=_SMURF_LINKS,
))
