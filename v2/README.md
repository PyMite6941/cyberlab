# cyberlab v2

An offline cyber range for the cyber class. `cyberlab` starts deliberately
vulnerable targets **on your own machine** (`127.0.0.1`), and you attack them
with the real tools: Firefox, curl, sqlmap, nmap, Wireshark. It then checks
your answers.

- **Runs on a stock Linux Mint** (Python 3.10+, standard library only). No internet.
- **Nothing leaves your machine.** Targets only listen on 127.0.0.1.
- **Your flags are yours.** Each workspace gets its own secret, so every
  student's flags are different.

The real tools come from the offline tools pack (`v2/tools-pack/`). The labs
also work with just Firefox and curl.

## Set up (once)

Copy this `v2` folder to the machine (USB stick, shared folder, or `git clone`),
then:

```bash
cd v2
./setup.sh          # makes `cyberlab` a command
```

Open a new terminal if it asks you to. Until then, `./bin/cyberlab` works the same.

## Use it

```bash
cyberlab list                      # challenges and your progress
cyberlab start web-sqli            # starts the target and shows the goal
cyberlab hint web-sqli             # one more hint each time
cyberlab submit web-sqli FLAG{...} # check your answer
cyberlab learn web-sqli             # review the lesson, commands and defenses
cyberlab stop                      # stop every running target
cyberlab report --name "Your Name" -o ~/Desktop/report.txt   # progress to hand in
cyberlab reset                     # delete your workspace and progress
```

Example: `cyberlab start web-sqli` prints a URL like `http://127.0.0.1:8080/login`.
Open it in Firefox, or use curl or sqlmap, find the flag, and submit it.
After a correct answer, cyberlab explains what happened, why it matters in
practice, gives lab-scoped commands to try, and lists defenses. Run
`cyberlab learn <id>` any time to review that debrief. Start the challenge
first if its target or workspace files are not currently available.

Your progress, the targets' logs and any challenge files live in `~/cyberlab/`
(set `CYBERLAB_HOME` to use another folder).

## Challenges

| ID | Track | Level | What you do |
|----|-------|-------|-------------|
| `web-sqli` | web | easy | SQL injection: log in as admin without the password |
| `web-xss` | web | easy | Run JavaScript through a reflected search term |
| `web-idor` | web | easy | Access a record without an object-level permission check |
| `web-session` | web | easy | Forge an unsigned JWT role claim; compare signature verification |
| `web-upload` | web | medium | Bypass a double-extension upload check; compare private storage and validation |
| `web-gobuster` | web | medium | Find a forgotten directory and its exposed backup |
| `net-http-creds` | network | easy | Recover a password sent in cleartext HTTP |
| `net-port-scan` | network | medium | Find the host port-scanning the server |
| `net-dns-tunnel` | network | hard | Spot the domain tunneling data over DNS |
| `net-nmap` | network | medium | Find forgotten services with nmap |
| `dict-john` | passwords | easy | Crack weak local password hashes with John the Ripper |
| `dict-hydra` | passwords | medium | Audit a local HTTP login with Hydra |
| `web-log-forensics` | logs | easy | Identify a traversal request and cite its access-log line |

More are coming: see [DESIGN.md](DESIGN.md).

### AP Cybersecurity alignment

| Challenge | Unit/topic | Skills practiced |
|-----------|------------|------------------|
| `dict-hydra` | Units 1, 4; 4.2 Authentication | Analyze Risk, Mitigate Risk, Detect Attacks |
| `dict-john` | Units 4–5; 4.2 Authentication, 5.2 Access Controls | Analyze Risk, Mitigate Risk |
| `net-http-creds` | Unit 3; 3.1 Network Vulnerabilities and Attacks | Analyze Risk, Detect Attacks |
| `net-nmap` | Unit 3; 3.1, 3.3 Segmentation, 3.4 Firewalls | Analyze Risk, Detect Attacks |
| `net-port-scan` | Unit 3; 3.1, 3.5 Detecting Network Attacks | Analyze Risk, Detect Attacks |
| `net-dns-tunnel` | Unit 3; 3.5 Detecting Network Attacks | Detect Attacks |
| `web-sqli` | Unit 5; 5.1 Application and Data Vulnerabilities and Attacks | Analyze Risk, Mitigate Risk, Detect Attacks |
| `web-xss` | Unit 5; 5.1 Application and Data Vulnerabilities and Attacks | Analyze Risk, Mitigate Risk, Detect Attacks |
| `web-idor` | Unit 5; 5.2 Managerial Controls and Access Controls | Analyze Risk, Mitigate Risk |
| `web-session` | Unit 4; 4.2 Authentication | Analyze Risk, Mitigate Risk, Detect Attacks |
| `web-upload` | Unit 5; 5.1 Application and Data Vulnerabilities and Attacks | Analyze Risk, Mitigate Risk, Detect Attacks |
| `web-gobuster` | Unit 5; 5.1 Application and Data Vulnerabilities and Attacks | Analyze Risk, Detect Attacks |
| `web-log-forensics` | Unit 5; 5.6 Detecting Attacks on Data and Applications | Detect Attacks, Analyze Risk, Mitigate Risk |

`cyberlab learn <id>` shows the challenge's alignment alongside its debrief.

## For the teacher

- **Collecting progress:** students run
  `cyberlab report --name "Their Name" -o ~/Desktop/report.txt` and hand in the
  file. It lists every challenge, when it was solved, and how many hints it took.
  Add `--json` for a machine-readable version if you want to combine a class's
  results.
- **What a report can show:** it's a summary, not proof. Everything lives on the
  student's machine, so a determined student could edit it. The **Workspace** ID
  is a hash of that student's secret: two students handing in the same ID worked
  in the same workspace. To be sure someone solved a challenge, ask them to show it.
- Flags come from a random secret in each student's `~/cyberlab/.state.json`,
  so copying a classmate's flag doesn't work. The secret is on the student's
  machine, so this is a deterrent, not proof of work.
- `cyberlab reset` gives a student a clean slate (new secret, new flags).

## Develop

```bash
cd v2 && python3 -m unittest discover -s tests -v
```

Adding a challenge: copy `cyberlab/challenges/web_sqli.py`, change the fields,
`setup()` and (if the answer isn't a flag) `check()`, then import it at the
bottom of `cyberlab/challenges/__init__.py`.
