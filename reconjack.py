#!/usr/bin/env python3
"""
Reconjack CLI
-------------------
A command-line recon helper that generates Google/Shodan/GitHub dork queries
for a target domain, organized by category. For sources with a real public
API (crt.sh, etc.), it fetches actual results instead of just building a
dork query.

Use only against domains you are authorized to test (active bug bounty
program, VDP, or your own assets).
"""

import argparse
import sys
import webbrowser
import urllib.parse
import json

try:
    import requests
except ImportError:
    requests = None


# ---------------------------------------------------------------------------
# Dork templates, organized by category.
# {domain} is substituted at runtime.
# ---------------------------------------------------------------------------

DORKS = {
    "config_files": {
        "label": "Configuration Files",
        "queries": [
            'site:{domain} ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini',
        ],
    },
    "database_files": {
        "label": "Database Files",
        "queries": [
            'site:{domain} ext:sql | ext:dbf | ext:mdb',
        ],
    },
    "log_files": {
        "label": "Log Files",
        "queries": [
            'site:{domain} ext:log',
        ],
    },
    "backup_files": {
        "label": "Backup and Old Files",
        "queries": [
            'site:{domain} ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup',
        ],
    },
    "login_pages": {
        "label": "Login Pages",
        "queries": [
            'site:{domain} inurl:login | inurl:signin | inurl:logon',
        ],
    },
    "sql_errors": {
        "label": "SQL Errors",
        "queries": [
            'site:{domain} intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near"',
        ],
    },
    "apache_config": {
        "label": "Apache Config Files",
        "queries": [
            'site:{domain} ext:cfg | ext:conf intext:"apache"',
        ],
    },
    "robots": {
        "label": "Robots.txt File",
        "queries": [
            'https://{domain}/robots.txt',
        ],
    },
    "directory_listing": {
        "label": "Directory Listing",
        "queries": [
            'site:{domain} intitle:"index of"',
        ],
    },
    "exposed_documents": {
        "label": "Publicly Exposed Documents",
        "queries": [
            'site:{domain} ext:doc | ext:docx | ext:pdf | ext:xls | ext:xlsx | ext:ppt | ext:pptx',
        ],
    },
    "phpinfo": {
        "label": "phpinfo()",
        "queries": [
            'site:{domain} ext:php intitle:"phpinfo()"',
        ],
    },
    "finding_backdoors": {
        "label": "Finding Backdoors",
        "queries": [
            'site:{domain} intitle:"index of" "shell" | "c99" | "r57" | "webshell"',
        ],
    },
    "htaccess": {
        "label": ".htaccess Sensitive Files",
        "queries": [
            'site:{domain} ext:htaccess | ext:htpasswd',
        ],
    },
    "subdomains_google": {
        "label": "Find Subdomains (Google)",
        "queries": [
            'site:*.{domain} -www',
        ],
    },
    "install_files": {
        "label": "Install / Setup Files",
        "queries": [
            'site:{domain} inurl:install | inurl:setup',
        ],
    },
    "open_redirects": {
        "label": "Open Redirects",
        "queries": [
            'site:{domain} inurl:redirect= | inurl:url= | inurl:return= | inurl:next=',
        ],
    },
    "struts_rce": {
        "label": "Apache STRUTS RCE",
        "queries": [
            'site:{domain} ext:action | ext:do',
        ],
    },
    "wordpress": {
        "label": "WordPress",
        "queries": [
            'site:{domain} inurl:wp-content | inurl:wp-admin',
        ],
    },
    "wordpress_2": {
        "label": "Find WordPress #2",
        "queries": [
            'site:{domain} inurl:wp-config.php.bak | inurl:wp-config.php.old',
        ],
    },
    "third_party_exposure": {
        "label": "3rd Party Exposure",
        "queries": [
            'site:trello.com | site:gitlab.com "{domain}"',
        ],
    },
    "security_headers": {
        "label": "Check Security Headers",
        "queries": [
            'https://securityheaders.com/?q={domain}',
        ],
    },
    "stackoverflow": {
        "label": "Search in Stack Overflow",
        "queries": [
            'site:stackoverflow.com "{domain}"',
        ],
    },
    "pastebin": {
        "label": "Find Pastebin Entries",
        "queries": [
            'site:pastebin.com "{domain}"',
        ],
    },
    "employees_linkedin": {
        "label": "Employees on LinkedIn",
        "queries": [
            'site:linkedin.com/in "{domain}"',
        ],
    },
    "sensitive_files": {
        "label": "Sensitive Files",
        "queries": [
            'site:{domain} ext:key | ext:pem | ext:ppk | ext:p12 | ext:pfx',
        ],
    },
    "find_subdomains_2": {
        "label": "Find Sub-Subdomains",
        "queries": [
            'site:*.*.{domain}',
        ],
    },
    "cross_domain": {
        "label": "Test CrossDomain",
        "queries": [
            'https://{domain}/crossdomain.xml',
        ],
    },
    "github_search": {
        "label": "Search in GitHub",
        "queries": [
            'https://github.com/search?q={domain}&type=code',
        ],
    },
    "swf_google": {
        "label": "Find .swf File (Google)",
        "queries": [
            'site:{domain} ext:swf',
        ],
    },
    "openbugbounty": {
        "label": "Search in OpenBugBounty",
        "queries": [
            'https://www.openbugbounty.org/search/?search={domain}',
        ],
    },
    "wayback_wordpress": {
        "label": "Find WordPress [Wayback Machine]",
        "queries": [
            'https://web.archive.org/cdx/search/cdx?url=*.{domain}/wp-content/*&output=text&fl=original&collapse=urlkey',
        ],
    },
    "wayback_swf": {
        "label": "Find .swf File (Wayback Machine)",
        "queries": [
            'https://web.archive.org/cdx/search/cdx?url=*.{domain}/*.swf&output=text&fl=original&collapse=urlkey',
        ],
    },
    "reddit_search": {
        "label": "Search in Reddit",
        "queries": [
            'site:reddit.com "{domain}"',
        ],
    },
    "threatcrowd": {
        "label": "Check in ThreatCrowd",
        "queries": [
            'https://www.threatcrowd.org/domain.php?domain={domain}',
        ],
    },
    "git_folder": {
        "label": ".git Folder Exposure",
        "queries": [
            'https://{domain}/.git/config',
        ],
    },
    "youtube": {
        "label": "YouTube Mentions",
        "queries": [
            'site:youtube.com "{domain}"',
        ],
    },
    "s3_buckets": {
        "label": "S3 Buckets",
        "queries": [
            'site:s3.amazonaws.com "{domain}"',
        ],
    },
    "what_cms": {
        "label": "What CMS?",
        "queries": [
            'https://whatcms.org/?s={domain}',
        ],
    },
    "shodan": {
        "label": "Search in SHODAN",
        "queries": [
            'https://www.shodan.io/search?query=hostname:{domain}',
        ],
    },
    "censys_domains": {
        "label": "Check in CENSYS [Domains]",
        "queries": [
            'https://search.censys.io/search?resource=hosts&q={domain}',
        ],
    },
    "publicwww": {
        "label": "Sourcecode - PublicWWW",
        "queries": [
            'https://publicwww.com/websites/%22{domain}%22/',
        ],
    },
    "reverse_ip": {
        "label": "Reverse IP Lookup",
        "queries": [
            'https://api.hackertarget.com/reverseiplookup/?q={domain}',
        ],
    },
}

# crt.sh has a real JSON API -- this is fetched live, not dorked.
CRTSH_LABEL = "Certificate Transparency (crt.sh) -- live fetch"


def build_url_or_query(template: str, domain: str) -> str:
    """Fill in {domain} and, for plain dork strings (not URLs), wrap as a
    Google search URL. URL templates pass through filled-in as-is."""
    filled = template.format(domain=domain)
    if filled.startswith("http://") or filled.startswith("https://"):
        return filled
    return "https://www.google.com/search?q=" + urllib.parse.quote(filled)


def fetch_crtsh(domain: str):
    """Hit the real crt.sh JSON API and return a deduplicated list of
    subdomains found in certificate transparency logs."""
    if requests is None:
        print("[!] The 'requests' library is required for live crt.sh lookups.")
        print("    Install it with: pip install requests")
        return []

    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    headers = {"User-Agent": "Mozilla/5.0 (compatible; reconjack-cli/1.0)"}
    try:
        resp = requests.get(url, headers=headers, timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, json.JSONDecodeError) as exc:
        print(f"[!] crt.sh lookup failed: {exc}")
        print("    Note: crt.sh rate-limits aggressively and is sometimes flaky --")
        print("    if this keeps failing, try again in a few minutes or from a different network.")
        return []

    names = set()
    for entry in data:
        value = entry.get("name_value", "")
        for line in value.splitlines():
            line = line.strip().lstrip("*.")
            if line:
                names.add(line)
    return sorted(names)


def run_category(key: str, domain: str, mode: str):
    """mode: 'print', 'open', or 'both'"""
    info = DORKS[key]
    print(f"\n=== {info['label']} ===")
    for template in info["queries"]:
        url = build_url_or_query(template, domain)
        if mode in ("print", "both"):
            print(url)
        if mode in ("open", "both"):
            webbrowser.open(url)


def list_categories():
    print("Available categories:\n")
    for key, info in DORKS.items():
        print(f"  {key:<22} {info['label']}")
    print(f"\n  {'crtsh':<22} {CRTSH_LABEL}")


def main():
    parser = argparse.ArgumentParser(
        prog="reconjack",
        description="Generate recon dork queries and fetch live data for a target domain. "
                     "Use only against domains you are authorized to test.",
    )
    parser.add_argument("-d", "--domain", help="Target domain, e.g. example.com")
    parser.add_argument(
        "-c", "--category",
        help="Run a single category (see --list for available keys)",
    )
    parser.add_argument(
        "-a", "--all",
        action="store_true",
        help="Run every category for the given domain",
    )
    parser.add_argument(
        "--mode",
        choices=["print", "open", "both"],
        default="print",
        help="print = show URLs only, open = launch browser, both = do both (default: print)",
    )
    parser.add_argument(
        "--crtsh",
        action="store_true",
        help="Fetch live subdomains from crt.sh certificate transparency logs",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List all available categories and exit",
    )
    parser.add_argument(
        "-o", "--output",
        help="Save crt.sh results to a file (only applies with --crtsh)",
    )

    args = parser.parse_args()

    if args.list:
        list_categories()
        sys.exit(0)

    if not args.domain:
        parser.error("the -d/--domain argument is required (unless using --list)")

    if args.crtsh:
        print(f"\n=== {CRTSH_LABEL} for {args.domain} ===")
        results = fetch_crtsh(args.domain)
        if results:
            for sub in results:
                print(sub)
            print(f"\n[+] {len(results)} unique subdomains found.")
            if args.output:
                with open(args.output, "w") as f:
                    f.write("\n".join(results) + "\n")
                print(f"[+] Saved to {args.output}")
        else:
            print("[!] No results returned.")

    if args.all:
        for key in DORKS:
            run_category(key, args.domain, args.mode)
    elif args.category:
        if args.category not in DORKS:
            print(f"[!] Unknown category: {args.category}")
            print("    Run with --list to see available categories.")
            sys.exit(1)
        run_category(args.category, args.domain, args.mode)
    elif not args.crtsh:
        parser.error("specify --category, --all, --crtsh, or --list")


if __name__ == "__main__":
    main()