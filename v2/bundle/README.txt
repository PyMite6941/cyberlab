cyberlab class bundle (Linux Mint 22.x, offline)
================================================

Everything for the cyber class in one folder: the cyberlab practice range
and the security tools (nmap, tshark, Wireshark, hydra, sqlmap, John the
Ripper, nikto, gobuster, curl, netcat). Nothing here needs internet.

Install (as your normal user, not with sudo):

    ./install.sh

It asks for your password once, for the tools. Then open a new terminal and:

    cyberlab list
    cyberlab start web-sqli

Already have the tools?   ./install.sh --skip-tools
More help:                 cyberlab --help, and cyberlab/README.md

  cyberlab/   the practice range (installed to ~/.local/share/cyberlab-app)
  tools/      the offline tools pack; tools/licenses/ has each package's license
