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
cyberlab stop                      # stop every running target
cyberlab report --name "Your Name" -o ~/Desktop/report.txt   # progress to hand in
cyberlab reset                     # delete your workspace and progress
```

Example: `cyberlab start web-sqli` prints a URL like `http://127.0.0.1:8080/login`.
Open it in Firefox, or use curl or sqlmap, find the flag, and submit it.

Your progress, the targets' logs and any challenge files live in `~/cyberlab/`
(set `CYBERLAB_HOME` to use another folder).

## Challenges

| ID | Track | Level | What you do |
|----|-------|-------|-------------|
| `web-sqli` | web | easy | SQL injection: log in as admin without the password |

More are coming: see [DESIGN.md](DESIGN.md).

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
