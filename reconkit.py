#!/usr/bin/env python3
"""reconkit - passive OSINT recon for a domain: certificate-transparency
subdomains, DNS records (via DNS-over-HTTPS), and TLS certificate details.
Passive by default; the optional --subs brute-force mode is active - use only
on domains you own or are authorized to test."""
import argparse, json, socket, ssl, sys, urllib.request, urllib.parse

DOH = "https://cloudflare-dns.com/dns-query"
RTYPES = {"A": 1, "NS": 2, "CNAME": 5, "SOA": 6, "MX": 15, "TXT": 16, "AAAA": 28, "CAA": 257}

def get_json(url, timeout):
    req = urllib.request.Request(url, headers={"Accept": "application/dns-json",
                                               "User-Agent": "reconkit/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.load(r)

def dns_records(domain, timeout):
    out = {}
    for name in RTYPES:
        try:
            d = get_json(f"{DOH}?name={urllib.parse.quote(domain)}&type={name}", timeout)
            ans = [a["data"] for a in d.get("Answer", []) if a.get("type") == RTYPES[name]]
            if ans: out[name] = sorted(ans)
        except Exception:
            pass
    return out

def crtsh_subdomains(domain, timeout):
    url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
    try:
        data = get_json(url, timeout)
    except Exception as e:
        return None, str(e)
    subs = set()
    for row in data:
        for n in row.get("name_value", "").split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith(domain): subs.add(n)
    return sorted(subs), None

def tls_cert(domain, timeout, port=443):
    ctx = ssl.create_default_context()
    with socket.create_connection((domain, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=domain) as s:
            c = s.getpeercert()
    sans = [v for t, v in c.get("subjectAltName", []) if t == "DNS"]
    return {"issuer": dict(x[0] for x in c.get("issuer", [])),
            "subject": dict(x[0] for x in c.get("subject", [])),
            "not_before": c.get("notBefore"), "not_after": c.get("notAfter"),
            "san_count": len(sans), "san_sample": sorted(sans)[:10]}

def resolve(wordlist, domain, timeout):
    found = []
    socket.setdefaulttimeout(timeout)
    for word in wordlist:
        host = f"{word.strip()}.{domain}"
        try: found.append((host, socket.gethostbyname(host)))
        except (socket.gaierror, socket.timeout, UnicodeError): pass
    return found

def main():
    ap = argparse.ArgumentParser(description="Passive OSINT recon for a domain.")
    ap.add_argument("domain", help="Target domain, e.g. example.com")
    ap.add_argument("--timeout", type=float, default=10.0)
    ap.add_argument("--subs", help="Wordlist file for ACTIVE subdomain brute force (authorized targets only).")
    ap.add_argument("-o", "--output", help="Write JSON report to this file.")
    args = ap.parse_args()
    d = args.domain.strip().lower()
    report = {"domain": d}

    print(f"[*] DNS records for {d} (via DNS-over-HTTPS)")
    report["dns"] = dns_records(d, args.timeout)
    for t, vals in report["dns"].items():
        for v in vals[:10]: print(f"    {t:<6} {v}")

    print(f"\n[*] Certificate-transparency subdomains (crt.sh)")
    subs, err = crtsh_subdomains(d, max(args.timeout, 30))
    if err:
        print(f"    crt.sh lookup failed: {err}"); report["ct_subdomains"] = []
    else:
        report["ct_subdomains"] = subs
        print(f"    {len(subs)} unique name(s)")
        for s in subs[:25]: print(f"    {s}")
        if len(subs) > 25: print(f"    ... and {len(subs) - 25} more")

    try:
        print(f"\n[*] TLS certificate on {d}:443")
        report["tls"] = tls_cert(d, args.timeout)
        print(f"    issuer : {report['tls']['issuer'].get('organizationName', '?')} / {report['tls']['issuer'].get('commonName', '?')}")
        print(f"    expires: {report['tls']['not_after']}")
        print(f"    SANs   : {report['tls']['san_count']} names")
    except Exception as e:
        print(f"    TLS check failed: {e}"); report["tls"] = None

    if args.subs:
        print(f"\n[*] ACTIVE subdomain brute force (authorized use only)")
        words = [w for w in open(args.subs) if w.strip()]
        hits = resolve(words, d, args.timeout)
        report["bruteforce_subdomains"] = [{"host": h, "ip": ip} for h, ip in hits]
        for h, ip in hits: print(f"    {h:<40} {ip}")
        print(f"    {len(hits)}/{len(words)} resolved")

    if args.output:
        with open(args.output, "w") as f: json.dump(report, f, indent=2)
        print(f"\n[*] JSON written to {args.output}")

if __name__ == "__main__":
    main()
