# cyberlab expansion roadmap

The v2 challenge range is the only supported application. Its core loop is:
start an isolated local target or create an exercise file, investigate it with
standard tools, then submit an answer for immediate feedback.

## Current baseline

- Sixteen challenges across web, network and logs, each with a real local
  target or synthetic evidence file, plus per-workspace flags, hints,
  progress, target lifecycle, text/JSON reports, and written debriefs
  (`cyberlab learn <id>`).
- Python standard library runtime and offline tests.
- Optional Linux Mint 22.x offline tools pack.

## Recommended next steps

1. **Broaden the web track:** add isolated, independently testable challenges
   for access-control mistakes, reflected input handling, and unsafe upload
   validation. Give each challenge its own target behavior, hints, checker, and
   tests; do not make a class exercise depend on a real external service.
2. **Add offline evidence labs:** provide generated packet captures and log
   files students can inspect with Wireshark/tshark or standard text tools.
   Include expected observations and checks so these labs remain usable without
   network access.
3. **Build a log-analysis track:** create realistic but synthetic web, SSH, and
   operating-system event logs, then add guided investigation tasks for finding
   suspicious activity and explaining the evidence.
4. **Improve class operations:** support difficulty filtering, clearer
   per-challenge state, and a teacher-friendly way to combine reports while
   minimizing identifying data. Keep reports explicit that local progress is
   not tamper-proof verification.
5. **Expand deployment coverage only with tests:** retain Linux Mint as the
   supported baseline; add other platforms only after target start/stop,
   workspace paths, and installer behavior are verified there.

## Guardrails for new labs

- Keep vulnerable targets bound to `127.0.0.1`; never add real-world scanning
  or third-party network callbacks to the default experience.
- Use synthetic datasets and per-workspace answers; don't put real credentials
  or student data in the repository.
- Add unit tests for the checker and an end-to-end CLI test for each new
  challenge. Check that target shutdown and workspace cleanup work as expected.
- Keep optional tools clearly separated from the standard-library runtime and
  document any platform or school-policy requirements.

See [v2/DESIGN.md](v2/DESIGN.md) for the architecture and existing milestones.
