# reconjack-cli

A command-line recon helper. Generates Google/Shodan/GitHub/crt.sh-style dork
queries for a target domain, organized by category, inspired by the
button-driven workflow of GUI recon dorking tools — built as a scriptable CLI
instead.

For sources with a real public API (crt.sh certificate transparency), it
fetches live data directly instead of just building a search-engine query.

```
> usage
[+] list every category
[+] run one category, or all of them, for a domain
[+] print URLs, open them in the browser, or both
[+] pull live subdomains from crt.sh
```

## Install

```bash
pip install -r requirements.txt
```

## Usage

List all available categories:
```bash
python reconjack.py --list
```

Run a single category:
```bash
python reconjack.py -d example.com -c login_pages
```

Run everything for a domain, opening each query in the browser:
```bash
python reconjack.py -d example.com --all --mode open
```

Fetch live subdomains from crt.sh and save to a file:
```bash
python reconjack.py -d example.com --crtsh -o subs.txt
```

## Modes

- `print` (default) — just show the URL/query
- `open` — launch it in your default browser
- `both` — do both

## Scope

Use only against domains you are explicitly authorized to test — an active
bug bounty program, a vulnerability disclosure policy, or your own
infrastructure.