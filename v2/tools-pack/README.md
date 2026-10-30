# cyberlab tools pack

Real security tools for the cyber class, installable on the school's Linux Mint
22.x machines **without internet**:

nmap, tshark, Wireshark, hydra, sqlmap, John the Ripper, nikto, gobuster, curl, netcat

## Install (on each school machine)

1. Copy `cyberlab-tools-noble-amd64.tar.gz` to the machine (USB stick or shared folder).
2. Unpack it and run the installer:

   ```bash
   tar xzf cyberlab-tools-noble-amd64.tar.gz
   cd cyberlab-tools-noble-amd64
   sudo ./install.sh
   ```

It prints where each tool landed, or `MISSING` if something didn't install.

- **No internet needed.** apt installs only from the pack's `debs/` folder.
- **Safe for the system.** It installs what's missing and upgrades a library only
  if a tool needs a newer one. It never downgrades anything and doesn't touch
  unrelated packages. Your normal apt sources are left as they are.
- **Wireshark** is set so only root can capture live traffic. The labs only read
  pcap files, which works for every user.
- **Built for Mint 22.x (Ubuntu 24.04 "noble", amd64) only.** The installer
  refuses to run on anything else.

Before installing these on school machines, check with the teacher or school IT:
scanning and password-cracking tools can be against the acceptable-use policy or
trip network monitoring, even when they're only used against `127.0.0.1`.

## Get the pack

GitHub Actions builds it: the **tools-pack** workflow runs when anything in
`v2/tools-pack/` changes, or by hand from the Actions tab (**Run workflow**).
Download `cyberlab-tools-noble-amd64` from the run's **Artifacts**.

To build it yourself on any machine with Docker:

```bash
docker run --rm --platform linux/amd64 -v "$PWD":/work -w /work \
    ubuntu:24.04 bash v2/tools-pack/build.sh out
```

## Change the tools

Edit `tools.txt` (Ubuntu package names, one per line). The build bundles each
tool's full dependency chain, so nothing else needs listing.

## Licenses

Each package's license notice is in the pack's `licenses/` folder. nmap is under
the Nmap Public Source License; check its terms before redistributing the pack
outside the class.
