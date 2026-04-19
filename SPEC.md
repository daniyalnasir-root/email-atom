name: email-atom
purpose: Generate and diff RFC 5321/5322 email-parser-disagreement variants used to bypass app-layer access control via the recipient address.
language: python
why_language: Python's stdlib `email` ships two parsers (legacy `email.utils.parseaddr` and policy-based `email.headerregistry.Address`) which disagree on the same input — perfect substrate for showing which atom-splitting variant slips past which parser.
features:
- Variant generator: encoded-word, quoted local-part, RFC 5321 source route, comment, multiple-@, CFWS, IDN homoglyph, unicode-fold
- Multi-parser diff: shows what each of 4 parsers returns for the same address
- Highlights disagreements where one parser returns the trusted domain and another returns the attacker domain
- Optional --probe mode sends each variant to a URL field and reports response code/length deltas
- NO_COLOR / no-tty respected; --json output for piping
input_contract: a base email address (like victim@target.com) and an attacker-controlled domain (like attacker.example)
output_contract: table of variants × parsers × resolved domain, with disagreements flagged; or JSON
safe_test_target: local fixture (example variants from the research), plus optional --probe against http://localhost:3000 or httpbin.org/post
synonym_names:
- mailparse-diff
- parseaddr-fuzz
- email-confuse
source_inspiration_url: https://portswigger.net/research/splitting-the-email-atom
