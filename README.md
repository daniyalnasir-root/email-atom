# email-atom

Generate and diff email parser-disagreement variants for access-control bypass testing.

A small CLI for the technique Gareth Heyes published as *Splitting the Email Atom* (PortSwigger, 2024): when a webapp checks the recipient domain with one parser and the SMTP layer routes mail with a different parser, you can register or reset against a trusted address while the message lands in your inbox. This tool produces the variants and shows you which parser sees what.

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Status: active](https://img.shields.io/badge/status-active-brightgreen.svg)](#)

## Overview

Email addresses look simple and aren't. RFC 5321 (SMTP envelope) and RFC 5322 (message header) disagree on what counts as the local part, the domain, a comment, an obs-route, a quoted string. A signup gate, an OAuth identity provider, and the mail server downstream are usually three different parsers reading the same string.

`email-atom` enumerates fifteen variants drawn from that disagreement surface and runs the same string through four common parsers (`email.utils.parseaddr`, `email.headerregistry.Address`, a naive trailing-`@` regex, an SMTP-style strip-quoted-block routine). When two parsers extract two different domains from the same address, that's a candidate bypass.

The optional `probe` mode submits each variant to a target form field and diffs the response code and length against the baseline, surfacing variants the application accepts.

## Features

Fifteen built-in variants covering the most productive RFC 5321/5322 disagreement patterns: quoted local-part, source route, encoded-word, multiple-`@`, CFWS folding, punycode homoglyph, NUL injection, and a handful more. Each variant runs through four parsers and gets a side-by-side table; the cases where one parser sees the trusted domain and another sees the attacker domain are highlighted in red.

- JSON output for piping into Burp, ffuf, or your own scripts
- HTTP probe mode with response-code and length delta reporting
- Pure Python 3.9+ standard library, no third-party install step
- `NO_COLOR` and non-tty environments respected, exit codes `0`/`1`/`2`

## Installation

```bash
git clone https://github.com/daniyalnasir-root/email-atom.git
cd email-atom
python3 cli.py -h
```

No `pip install` step. The script imports only the standard library.

## Usage

```bash
# Show every variant and how four parsers see each one
python3 cli.py gen --email victim@target.com --attacker attacker.example

# Same, but as JSON for downstream tooling
python3 cli.py gen --email victim@target.com --attacker attacker.example --json | jq

# POST each variant to a signup endpoint and diff response codes and length
python3 cli.py probe \
    --email victim@target.com \
    --attacker attacker.example \
    --url https://app.example.com/api/signup \
    --field email
```

## Command Line Options

### `gen`: local variant generation and parser diff

| Flag | Required | Description |
|------|----------|-------------|
| `--email` | yes | Base address `local@target` to mutate |
| `--attacker` | yes | Attacker-controlled domain to splice in |
| `--json` | no | Emit JSON instead of the colored table |

### `probe`: submit each variant to a remote field

| Flag | Required | Description |
|------|----------|-------------|
| `--email` | yes | Base address `local@target` |
| `--attacker` | yes | Attacker-controlled domain |
| `--url` | yes | Endpoint to POST against |
| `--field` | no | Form field name (default `email`) |
| `--method` | no | HTTP method (default `POST`) |
| `--timeout` | no | Per-request timeout in seconds (default `10`) |

## Output Example

```
$ python3 cli.py gen --email victim@target.com --attacker attacker.example

variant                parser                   domain
------------------------------------------------------------------------------
baseline               stdlib.parseaddr         target.com
baseline               headerregistry.Address   target.com
baseline               naive.regex              target.com
baseline               rfc5321.rcpt             target.com
quoted-localpart       stdlib.parseaddr         target.com"@attacker.example
quoted-localpart       headerregistry.Address   attacker.example
quoted-localpart       naive.regex              attacker.example
quoted-localpart       rfc5321.rcpt             attacker.example
  ↳ diverge: 2 distinct domains
comment-before-domain  stdlib.parseaddr         target.com
comment-before-domain  headerregistry.Address   target.com
comment-before-domain  naive.regex              <nomatch>
comment-before-domain  rfc5321.rcpt             (attacker.example)target.com
  ↳ split: one parser sees trusted, another sees attacker
multiple-at-rfc5322    stdlib.parseaddr         <nodomain>
multiple-at-rfc5322    headerregistry.Address   <error: HeaderParseError>
multiple-at-rfc5322    naive.regex              attacker.example
multiple-at-rfc5322    rfc5321.rcpt             attacker.example
```

The full unabridged output of both `gen` and `probe` is in [`examples/`](examples/).

## Legal Disclaimer

This tool is for authorized security testing and educational use only.
Run it only against systems you own or have explicit written permission to test.
The author accepts no liability for misuse. Unauthorized use may violate
local, state, or federal law.

## Author

**Daniyal Nasir** is a senior **Cybersecurity Consultant**, **Certified Ethical Hacker**, and provider of **professional penetration testing services** with over a decade of experience in **web application security**, **API security testing**, **mobile application pentesting**, **source code review**, and end-to-end **VAPT consulting** for Fortune 500 organisations and global SaaS platforms. Active **bug bounty hunter** with a track record of **responsible vulnerability disclosure** to major tech companies. Certifications: **OSCP**, **LPT (Master)**, **CPENT**, **CEH**, **CISA**, **CISM**, and **CASP+**.

* LinkedIn: https://www.linkedin.com/in/daniyalnasir
* Website:  https://www.daniyalnasir.com

## License

MIT — see [LICENSE](LICENSE).
