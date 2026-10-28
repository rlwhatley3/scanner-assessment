# Scan test documents

Sample inputs for exercising the scanner. Paste a file into the Playground, or
feed it to the engine directly.

**Every credential here is fake.** Values were randomly generated to match each
provider's format; none of them are live. Placeholder and documented example values
(`AKIAIOSFODNN7EXAMPLE`, `YOUR_API_KEY_HERE`, `ghp_xxxx…`) are used on purpose to
test placeholder classification.

The same fake values are reused across files, so a finding can be traced back to one
known value.

| File | Type | What it exercises |
|---|---|---|
| `app.env` | dotenv | AWS key pair, DB URL with password, Stripe secret and publishable keys, quoted and `export` variants |
| `docker-compose.yml` | YAML | Passwords in env and command args, Redis URL with password, GitHub token, Sentry DSN, `${VAR}` that should not match |
| `appsettings.json` | JSON | SQL connection string password, Google, Twilio and OpenAI keys, JWT signing key, a token inside escaped JSON |
| `config.toml` | TOML | DB URL password, fine-grained GitHub PAT, Anthropic key, a secret split across a multi-line string, a git SHA lookalike |
| `application.properties` | Java properties | `=`, `:` and whitespace separators, a value split by `\` line continuation, `${…}` placeholders |
| `deploy.sh` | Shell | Unsafe handling: secret echoed, password on the command line, token in a URL; bearer header, Slack webhook |
| `payment_client.py` | Python | Hardcoded fallback in `os.environ.get`, key logged and printed, key in URL, dict password, high-entropy unknown-format secret, `sk_test_YOUR_KEY_HERE` placeholder |
| `auth-server.ts` | TypeScript | JWT secret, npm token in a template literal, a signed JWT, password logged, token in a redirect URL |
| `storage.go` | Go | Raw-string AWS keys, a key built by concatenation (should not match a full pattern), credentials logged, password in `Sprintf` |
| `server-key.pem` | PEM / SSH | Multi-line RSA and OpenSSH private key blocks next to a certificate and public key that are not secrets |
| `Dockerfile` | Dockerfile | `ARG` and `ENV` secrets baked into the image, Slack bot token, a BuildKit secret mount that should not be reported |
| `main.tf` | Terraform / HCL | Provider keys, DB password, `sensitive` variable default, token inside a heredoc |
| `settings.xml` | XML | Passwords in elements, attributes on the element, CDATA, Maven-encrypted value, entity-escaped text |
| `migration.sql` | SQL | `PASSWORD '…'` and `IDENTIFIED BY`, API key in `INSERT`, bcrypt and argon2 hashes, `CHANGE_ME` placeholder |
| `access.log` | Log | Bearer JWT in headers, API key repeated on three lines, password in a log line, credentials in a git URL, Basic auth (base64 of a token), redacted value |
| `README-setup.md` | Markdown | Mostly placeholders and documented examples that should be classified as such, plus one real-looking key at the end |
| `clean-lookalikes.yaml` | Kubernetes YAML | **Expected clean.** SHAs, digests, UUIDs, MD5, SRI hashes, trace IDs and secret references by name only |
| `unicode-offsets.md` | Markdown | Multi-byte text (accents, CJK, emoji, ZWJ, combining marks, RTL) before matches, Cyrillic lookalike prefix, full-width colon |
| `mixed-line-endings.ini` | INI | CRLF, LF and a lone CR in one file, trailing whitespace after a value |
| `bundle.min.js` | Minified JS | One ~90 KB line; the same key four times, once inside a URL and a bearer header (overlap), two tokens joined with no separator |
