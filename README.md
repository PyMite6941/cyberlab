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
cyberlab learn web-sqli
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
| `web-sqli` | web | easy | Learn SQL injection and parameterized-query defenses |
| `web-xss` | web | easy | Learn reflected XSS and safe output encoding |
| `web-gobuster` | web | medium | Find an exposed backup with directory enumeration |
| `net-http-creds` | network | easy | Recover credentials from a synthetic HTTP capture |
| `net-port-scan` | network | medium | Identify a scanner from synthetic packet traffic |
| `net-dns-tunnel` | network | hard | Find a suspicious DNS domain in a synthetic capture |
| `net-nmap` | network | medium | Identify forgotten local services with nmap |
| `dict-john` | passwords | easy | Audit weak local password hashes |
| `dict-hydra` | passwords | medium | Audit a deliberately weak local login |

Correct submissions show a practical debrief with lab-scoped commands and
defenses. Use `cyberlab learn <id>` to revisit it later.

Targets bind to loopback only. `cyberlab stop` stops running targets, and
`cyberlab reset` deletes the local workspace after confirmation. Reports are
student-generated progress summaries, not proof of work.

## Development

```sh
python3 -m unittest discover -s v2/tests -v
./cyberlab.sh --help
```

For expansion priorities and design constraints, see [EXPANSION.md](EXPANSION.md)
and [v2/DESIGN.md](v2/DESIGN.md).
