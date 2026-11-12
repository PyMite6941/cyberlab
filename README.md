# cyberlab

An offline cyber range for classroom practice. The current standard is the v2
challenge-based range in `v2/`; the old `src` cyberterminal is no longer used.
Challenges run deliberately vulnerable targets on `127.0.0.1`, use per-workspace
flags, and save progress under `~/cyberlab` (or `CYBERLAB_HOME`).

The supported class environment is Linux Mint 22.x. The application uses
Python 3.10+ and the standard library. The optional offline tools pack is in
`v2/tools-pack/`.

## Quick start

On Linux Mint:

```sh
./install.sh
cyberlab list
cyberlab start web-sqli
cyberlab hint web-sqli
cyberlab submit web-sqli 'FLAG{...}'
cyberlab stop
cyberlab report --name "Your Name" -o ~/Desktop/report.txt
```

`./install.sh` installs a per-user `cyberlab` command link; it does not install
system packages. For a local checkout, `./cyberlab.sh list` runs the same v2
CLI without setup. `cyberlab.bat` is a Windows launcher for the CLI, but target
hosting is supported only in the documented Linux environment.

To install the optional tools pack on the class machines, use the bundled
offline archive and its installer. Read [v2/tools-pack/README.md](v2/tools-pack/README.md)
and follow school IT policy before installing or using security tools.

## Challenges and progress

| ID | Track | Level | Practice |
|----|-------|-------|----------|
| `web-sqli` | web | easy | SQL injection: log in as admin without the password |
| `web-xss` | web | easy | Reflected XSS: make the search box run your markup |
| `web-cookie` | web | medium | Privilege escalation by editing a role cookie |
| `web-idor` | web | medium | IDOR: read another account's invoice |
| `web-upload` | web | hard | Upload filter bypass: slip a webshell past the blocklist |
| `net-http-creds` | network | easy | Recover a password sent in cleartext HTTP |
| `net-port-scan` | network | medium | Find the host port-scanning the server |
| `net-dns-tunnel` | network | hard | Spot the domain tunneling data over DNS |
| `net-icmp-echo` | network | easy | Read ICMP echo traffic; find the host that replied |
| `net-smurf-victim` | network | medium | Find the target of a smurf amplification flood |
| `net-smurf-amp` | network | hard | Count the reflectors amplifying a smurf attack |
| `log-ssh-brute` | logs | easy | Find the IP that brute-forced SSH in auth.log |
| `log-web-scan` | logs | medium | Find the hidden path a web scan uncovered |
| `log-sudo-esc` | logs | hard | Find the user who escalated to root via sudo |
| `dict-john` | logs | easy | Crack a weak local password hash with John the Ripper |
| `dict-hydra` | logs | medium | Audit a local HTTP login with Hydra |

Targets bind to loopback only. `cyberlab stop` stops running targets, and
`cyberlab reset` deletes the local workspace after confirmation. Reports are
student-generated progress summaries, not proof of work.
Every solved challenge also has a written debrief: `cyberlab learn <id>`.

## Development

```sh
python3 -m unittest discover -s v2/tests -v
./cyberlab.sh --help
```

For expansion priorities and design constraints, see [EXPANSION.md](EXPANSION.md)
and [v2/DESIGN.md](v2/DESIGN.md).
