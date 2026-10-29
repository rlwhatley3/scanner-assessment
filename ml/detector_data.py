"""Synthetic training data for the secret detector.

Each sample is a whole document (an env file, YAML, JSON, code in several languages, shell, logs,
SQL, HTML, a lockfile, prose) with a label for every byte: 1 where the byte is part of a secret,
0 everywhere else. Secrets are planted among ordinary lines and among hard negatives that look
random but are not secret (hashes, digests, UUIDs, integrity strings, image data, public keys,
IDs, URLs, minified code, placeholders and references to secrets kept elsewhere).

Only the secret itself is labeled: the value, not its name or quotes; the password in a
connection string, not the whole URL; the token after `Bearer`. A private key is labeled from its
`-----BEGIN` line to the end of its first line of key data, so its finding starts where the key
does without the model having to see the whole block at once.

Real-shaped values are generated at random, so no secret-looking string is written here.
"""

import base64
import json
import random
import string
from dataclasses import dataclass, field

import numpy as np

UPPER = string.ascii_uppercase
LOWER = string.ascii_lowercase
DIGITS = string.digits
UPPER_DIGITS = UPPER + DIGITS
ALNUM = string.ascii_letters + DIGITS
LOWER_ALNUM = LOWER + DIGITS
BASE64 = ALNUM + "+/"
URLSAFE = ALNUM + "-_"
HEX = "0123456789abcdef"
PASSWORD_SYMBOLS = "!@#$%^&*-_=+?.,:;~"
# Every printable symbol that can sit inside a quoted string without escaping.
ALL_SYMBOLS = "!@#$%^&*()-_=+[]{}<>|~`,.;:/?"


@dataclass
class Doc:
    text: bytes
    labels: np.ndarray
    # (start, end, kind) byte ranges of what was planted, for reporting.
    secrets: list[tuple[int, int, str]] = field(default_factory=list)
    decoys: list[tuple[int, int, str]] = field(default_factory=list)


@dataclass
class Val:
    """A planted value: a secret (labeled 1) or a decoy (labeled 0, tracked for reporting)."""

    text: str
    kind: str
    secret: bool


Piece = str | Val


class Writer:
    def __init__(self) -> None:
        self.pieces: list[Piece] = []

    def put(self, *pieces: Piece | list[Piece]) -> None:
        for piece in pieces:
            if isinstance(piece, list):
                self.put(*piece)
            else:
                self.pieces.append(piece)

    def line(self, *pieces: Piece | list[Piece]) -> None:
        self.put(*pieces, "\n")

    def build(self) -> Doc:
        chunks: list[bytes] = []
        labels: list[np.ndarray] = []
        secrets, decoys = [], []
        offset = 0
        for piece in self.pieces:
            data = (piece.text if isinstance(piece, Val) else piece).encode()
            label = np.full(len(data), 1 if isinstance(piece, Val) and piece.secret else 0, np.uint8)
            if isinstance(piece, Val):
                (secrets if piece.secret else decoys).append((offset, offset + len(data), piece.kind))
            chunks.append(data)
            labels.append(label)
            offset += len(data)
        merged = merge_adjacent(secrets)
        return Doc(b"".join(chunks), np.concatenate(labels) if labels else np.zeros(0, np.uint8),
                   merged, decoys)


def merge_adjacent(spans: list[tuple[int, int, str]]) -> list[tuple[int, int, str]]:
    """A private key is planted as several labeled pieces; count it as one secret."""
    merged: list[tuple[int, int, str]] = []
    for start, end, kind in spans:
        if merged and merged[-1][1] == start and merged[-1][2] == kind:
            merged[-1] = (merged[-1][0], end, kind)
        else:
            merged.append((start, end, kind))
    return merged


def pick(r: random.Random, alphabet: str, n: int) -> str:
    return "".join(r.choice(alphabet) for _ in range(n))


def b64(r: random.Random, n_bytes: int, urlsafe: bool = False, pad: bool = True) -> str:
    raw = r.randbytes(n_bytes)
    out = (base64.urlsafe_b64encode(raw) if urlsafe else base64.b64encode(raw)).decode()
    return out if pad else out.rstrip("=")


def b64url_json(obj: dict) -> str:
    return base64.urlsafe_b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode().rstrip("=")


# ---------------------------------------------------------------------------------------------
# Words and names

WORDS = ("summer winter dragon monkey sunshine qwerty welcome tiger falcon orange coffee rocket "
         "shadow mustang silver purple banana hunter soccer guitar pepper maple river ocean thunder "
         "kitten panther cookie jasmine phoenix sparrow marble copper velvet harbor meadow lantern "
         "cobalt saffron nimbus quartz zephyr ember willow").split()
PROSE_WORDS = ("the a we it this that service deploy release build team staging production config "
               "database cluster migration request user account support issue update change fix "
               "should will can need please today tomorrow after before when while because and or "
               "but with without from into about our your their new old latest main branch review "
               "merge test check run start stop restart rollback monitor alert dashboard metrics "
               "latency error timeout retry queue worker job schedule backup restore region zone "
               "customer invoice report export import cache index search page api endpoint client "
               "server proxy network firewall rule policy access permission role group project").split()
UNICODE_BITS = ["café", "naïve", "über", "señor", "Zürich", "日本語のコメント", "设置", "конфиг",
                "✅", "🚀", "⚠️", "→", "—", "“quoted”", "µs", "°C", "©", "Ångström", "İstanbul"]
SERVICES = ("stripe github gitlab aws s3 gcp azure db postgres mysql redis mongo smtp mail sendgrid "
            "mailgun twilio slack discord openai anthropic sentry datadog newrelic algolia firebase "
            "auth oauth jwt session app api client service internal admin root master payment "
            "billing search storage cdn webhook signing encryption backend prod staging dev "
            "vault okta auth0 segment mixpanel heroku netlify vercel cloudflare npm pypi docker "
            "registry ci deploy bot crm erp ldap kafka rabbit elastic minio").split()
HOSTS = ("db.internal pg-primary.prod.svc mysql.example.org redis-01 cache.local 10.0.4.17 "
         "192.168.1.20 api.acme.io queue.prod.internal mongo-0.mongo.default.svc.cluster.local "
         "smtp.mailhost.net ldap.corp.local kafka-2:9092 localhost 127.0.0.1").split()
USERS = "admin root app deploy postgres svc_app backend ci readonly etl reporting web".split()
SECRET_NOUNS = {
    "key": ["api_key", "apikey", "key", "secret_key", "access_key", "app_key", "private_key",
            "master_key", "encryption_key", "signing_key", "license_key", "client_key"],
    "secret": ["secret", "client_secret", "app_secret", "consumer_secret", "webhook_secret",
               "shared_secret", "secret_token", "hmac_secret", "jwt_secret", "session_secret"],
    "token": ["token", "access_token", "auth_token", "api_token", "bearer_token", "refresh_token",
              "bot_token", "personal_access_token", "deploy_token", "service_token", "pat"],
    "password": ["password", "passwd", "pwd", "pass", "db_password", "admin_password",
                 "root_password", "user_password", "smtp_password", "redis_password",
                 "password_plain", "login_password", "passphrase", "pw"],
    "credential": ["credentials", "creds", "auth", "dsn", "connection_string", "conn_str",
                   "database_url", "url", "uri"],
}


def split_words(name: str) -> list[str]:
    return [w for w in name.replace("-", "_").split("_") if w]


def styled(r: random.Random, words: list[str], style: str | None = None) -> str:
    style = style or r.choice(["snake", "upper", "camel", "pascal", "kebab", "dotted", "flat"])
    if style == "snake":
        return "_".join(words)
    if style == "upper":
        return "_".join(words).upper()
    if style == "camel":
        return words[0] + "".join(w.capitalize() for w in words[1:])
    if style == "pascal":
        return "".join(w.capitalize() for w in words)
    if style == "kebab":
        return "-".join(words)
    if style == "dotted":
        return ".".join(words)
    return "".join(words)


def secret_name(r: random.Random, noun: str, style: str | None = None) -> str:
    words = split_words(r.choice(SECRET_NOUNS[noun]))
    if r.random() < 0.6:
        words = split_words(r.choice(SERVICES)) + words
    return styled(r, words, style)


def plain_name(r: random.Random, style: str | None = None) -> str:
    words = r.choice([["host"], ["port"], ["timeout"], ["region"], ["name"], ["log", "level"],
                      ["max", "connections"], ["retries"], ["bucket"], ["endpoint"], ["enabled"],
                      ["workers"], ["cache", "ttl"], ["base", "url"], ["user"], ["username"],
                      ["database"], ["path"], ["env"], ["debug"], ["version"], ["owner"],
                      ["queue", "name"], ["batch", "size"], ["pool", "size"], ["locale"],
                      ["feature", "flags"], ["email"], ["image"], ["replicas"], ["schema"]])
    if r.random() < 0.3:
        words = split_words(r.choice(SERVICES)) + words
    return styled(r, words, style)


def plain_value(r: random.Random) -> str:
    return r.choice([
        lambda: str(r.choice([80, 443, 3000, 5432, 6379, 8080, 9092, 27017])),
        lambda: str(r.randint(1, 5000)),
        lambda: r.choice(["true", "false", "yes", "no", "on", "off"]),
        lambda: r.choice(["us-east-1", "eu-west-2", "ap-south-1", "westeurope", "us-central1"]),
        lambda: r.choice(["info", "debug", "warn", "error"]),
        lambda: r.choice(HOSTS),
        lambda: f"https://{r.choice(['api', 'www', 'auth', 'cdn'])}.{r.choice(['acme', 'example', 'contoso', 'initech'])}.{r.choice(['com', 'io', 'dev', 'net'])}/{r.choice(['v1', 'v2', 'api', ''])}",
        lambda: f"{r.choice(USERS)}@{r.choice(['acme.com', 'example.org', 'corp.local'])}",
        lambda: f"{r.randint(0, 9)}.{r.randint(0, 30)}.{r.randint(0, 99)}",
        lambda: r.choice(["production", "staging", "development", "test"]),
        lambda: f"/var/lib/{r.choice(['app', 'data', 'postgres'])}/{r.choice(['cache', 'logs', 'tmp'])}",
        lambda: f"{r.choice(['web', 'worker', 'api'])}-{r.choice(['blue', 'green', 'canary'])}",
        lambda: r.choice(WORDS) + "-" + r.choice(WORDS),
        lambda: f"{r.randint(1, 60)}{r.choice(['s', 'm', 'h', 'ms'])}",
        lambda: r.choice(USERS),
        lambda: f"{r.choice(['nginx', 'postgres', 'redis', 'node', 'python'])}:{r.randint(1, 20)}.{r.randint(0, 9)}",
    ])()


# ---------------------------------------------------------------------------------------------
# Secrets. Each maker returns the value and the kind of name it is usually stored under.

def human_password(r: random.Random) -> str:
    style = r.random()
    if style < 0.35:
        word = r.choice(WORDS)
        word = word.capitalize() if r.random() < 0.6 else word
        return word + str(r.randint(1, 9999)) + r.choice(["!", "#", "$", "@", "?", "!!", "*", ""])
    if style < 0.55:
        leet = str.maketrans({"a": "@", "o": "0", "e": "3", "i": "1", "s": "$"})
        word = (r.choice(WORDS) + r.choice(WORDS)).translate(leet)
        return word.capitalize() + str(r.randint(0, 99))
    if style < 0.75:
        sep = r.choice(["-", ".", "_", " ", ""])
        words = [r.choice(WORDS) for _ in range(r.randint(3, 4))]
        return sep.join(w.capitalize() if r.random() < 0.3 else w for w in words) + (
            str(r.randint(0, 99)) if r.random() < 0.5 else "")
    return pick(r, ALNUM + PASSWORD_SYMBOLS, r.randint(10, 24))


def random_password(r: random.Random) -> str:
    n = r.randint(8, 32)
    alphabet = r.choice([ALNUM, ALNUM + PASSWORD_SYMBOLS, LOWER_ALNUM, ALNUM + "-_", ALNUM + ALL_SYMBOLS])
    return pick(r, alphabet, n)


def salt(r: random.Random) -> str:
    """A long generated key or salt drawn from every printable symbol, like a framework's
    generated secret key."""
    return pick(r, ALNUM + ALL_SYMBOLS, r.choice([40, 50, 64, 64]))


def webhook_url(r: random.Random) -> list[Piece]:
    """A chat or automation webhook: the URL's path is the credential."""
    return r.choice([
        lambda: ["https://hooks.slack.com/services/", Val(f"T{pick(r, UPPER_DIGITS, r.choice([8, 10]))}/B{pick(r, UPPER_DIGITS, r.choice([8, 10]))}/{pick(r, ALNUM, 24)}", "webhook_secret", True)],
        lambda: [f"https://{r.choice(['discord.com', 'discordapp.com'])}/api/webhooks/", Val(f"{pick(r, DIGITS, 18)}/{pick(r, URLSAFE, 68)}", "webhook_secret", True)],
        lambda: [f"https://{r.choice(['acme', 'contoso'])}.webhook.office.com/webhookb2/", Val(f"{rand_uuid(r)}@{rand_uuid(r)}/IncomingWebhook/{pick(r, HEX, 32)}/{rand_uuid(r)}", "webhook_secret", True)],
        lambda: ["https://hooks.zapier.com/hooks/catch/", Val(f"{pick(r, DIGITS, 7)}/{pick(r, LOWER_ALNUM, 6)}", "webhook_secret", True), "/"],
        lambda: [f"https://{r.choice(['api', 'hooks'])}.{r.choice(['acme', 'example', 'relay'])}.{r.choice(['io', 'dev'])}/webhooks/", Val(pick(r, URLSAFE, r.randint(24, 48)), "webhook_secret", True)],
    ])()


def jwt(r: random.Random) -> str:
    header = r.choice([{"alg": "HS256", "typ": "JWT"}, {"alg": "RS256", "typ": "JWT", "kid": pick(r, URLSAFE, 16)},
                       {"typ": "JWT", "alg": "ES256"}, {"alg": "HS512"}])
    payload = {"sub": r.choice([str(r.randint(1, 10**6)), pick(r, LOWER_ALNUM, 12)]),
               "iat": r.randint(1_500_000_000, 1_800_000_000)}
    if r.random() < 0.7:
        payload["exp"] = payload["iat"] + r.choice([900, 3600, 86400])
    if r.random() < 0.5:
        payload[r.choice(["name", "email", "role", "scope", "aud", "iss"])] = r.choice(
            ["admin", "read:all", "Jane Doe", "api", "https://auth.acme.io/", "user@acme.com"])
    sig = b64(r, r.choice([32, 64, 256]), urlsafe=True, pad=False)
    return f"{b64url_json(header)}.{b64url_json(payload)}.{sig}"


def novel_prefixed(r: random.Random) -> str:
    """A token from a made-up vendor: a short prefix, then random characters. No regex rule knows
    these, so the model has to go by shape and surroundings."""
    prefix = pick(r, LOWER, r.randint(2, 6)) + r.choice(["_", "-", "_live_", "_prod_", "-v1-", "_sk_", "_"])
    if r.random() < 0.3:
        prefix = prefix.upper()
    return prefix + pick(r, r.choice([ALNUM, LOWER_ALNUM, URLSAFE, HEX]), r.randint(20, 56))


def composite_token(r: random.Random) -> str:
    """Tokens made of parts: an account or bot id and a secret, a key with a region or shard
    suffix, or two random halves. Labeled whole."""
    return r.choice([
        lambda: pick(r, DIGITS, r.randint(8, 12)) + ":" + pick(r, URLSAFE, r.randint(30, 40)),
        lambda: pick(r, HEX, 32) + "-" + r.choice(["us", "eu", "dc", "ap"]) + str(r.randint(1, 20)),
        lambda: pick(r, ALNUM, r.randint(16, 24)) + "." + pick(r, ALNUM, r.randint(16, 40)),
        lambda: pick(r, HEX, 8) + ":" + pick(r, HEX, 8),
        lambda: rand_uuid(r) + ":" + pick(r, ALNUM, r.randint(20, 40)),
        lambda: pick(r, UPPER_DIGITS, r.randint(16, 20)) + ":" + pick(r, BASE64, 40),
        lambda: pick(r, LOWER_ALNUM, 8) + "-" + pick(r, LOWER_ALNUM, 4) + "-" + pick(r, ALNUM, 24),
    ])()


SECRET_MAKERS: dict[str, tuple[float, object, str]] = {
    # kind: (weight, maker, noun of the name it usually sits under)
    "aws_access_key": (3, lambda r: r.choice(["AKIA", "ASIA"]) + pick(r, UPPER_DIGITS, 16), "key"),
    "aws_secret_key": (3, lambda r: pick(r, BASE64, 40), "secret"),
    "github_token": (3, lambda r: r.choice(["ghp_", "gho_", "ghu_", "ghs_", "ghr_"]) + pick(r, ALNUM, 36), "token"),
    "github_pat": (1, lambda r: "github_pat_" + pick(r, ALNUM, 22) + "_" + pick(r, ALNUM, 59), "token"),
    "gitlab_token": (2, lambda r: "glpat-" + pick(r, URLSAFE, 20), "token"),
    "slack_token": (2, lambda r: r.choice(["xoxb-", "xoxp-", "xoxe-", "xapp-1-"]) + pick(r, DIGITS, 12)
                    + "-" + pick(r, DIGITS, 13) + "-" + pick(r, ALNUM, 24), "token"),
    "stripe_key": (2, lambda r: r.choice(["sk_live_", "rk_live_"]) + pick(r, ALNUM, r.choice([24, 99])), "key"),
    "google_api_key": (2, lambda r: "AIza" + pick(r, URLSAFE, 35), "key"),
    "sendgrid_key": (1, lambda r: "SG." + pick(r, URLSAFE, 22) + "." + pick(r, URLSAFE, 43), "key"),
    "llm_api_key": (2, lambda r: r.choice([
        lambda: "sk-" + pick(r, ALNUM, 48),
        lambda: "sk-proj-" + pick(r, URLSAFE, r.randint(80, 150)),
        lambda: "sk-ant-api03-" + pick(r, URLSAFE, 93) + "AA",
    ])(), "key"),
    "npm_token": (1, lambda r: "npm_" + pick(r, ALNUM, 36), "token"),
    "pypi_token": (1, lambda r: "pypi-AgEIcHlwaS5vcmc" + pick(r, URLSAFE, r.randint(60, 140)), "token"),
    "hf_token": (1, lambda r: "hf_" + pick(r, string.ascii_letters, 34), "token"),
    "twilio_key": (1, lambda r: "SK" + pick(r, HEX, 32), "key"),
    "mailgun_key": (1, lambda r: "key-" + pick(r, HEX, 32), "key"),
    "digitalocean_token": (1, lambda r: r.choice(["dop_v1_", "doo_v1_"]) + pick(r, HEX, 64), "token"),
    "shopify_token": (1, lambda r: r.choice(["shpat_", "shpss_", "shpca_"]) + pick(r, HEX, 32), "token"),
    "azure_storage_key": (1, lambda r: b64(r, 64), "key"),
    "novel_prefixed": (6, novel_prefixed, "token"),
    "generic_hex": (4, lambda r: pick(r, HEX if r.random() < 0.8 else HEX.upper(), r.choice([24, 32, 40, 48, 64])), "key"),
    "generic_alnum": (5, lambda r: pick(r, ALNUM, r.randint(16, 64)), "key"),
    "generic_base64": (4, lambda r: b64(r, r.randint(18, 64), urlsafe=r.random() < 0.3, pad=r.random() < 0.7), "secret"),
    "uuid_secret": (1, lambda r: str(rand_uuid(r)), "key"),
    "password": (10, human_password, "password"),
    "random_password": (5, random_password, "password"),
    "jwt": (3, jwt, "token"),
    "composite_token": (3, lambda r: composite_token(r), "token"),
    "salt": (2, salt, "secret"),
}
SHAPED = {"aws_access_key", "github_token", "github_pat", "gitlab_token", "slack_token", "stripe_key",
          "google_api_key", "sendgrid_key", "llm_api_key", "npm_token", "pypi_token", "hf_token",
          "digitalocean_token", "shopify_token", "jwt", "novel_prefixed", "mailgun_key", "composite_token"}


def make_secret(r: random.Random, kinds: list[str] | None = None) -> tuple[Val, str]:
    pool = kinds or list(SECRET_MAKERS)
    kind = r.choices(pool, weights=[SECRET_MAKERS[k][0] for k in pool])[0]
    _, maker, noun = SECRET_MAKERS[kind]
    return Val(maker(r), kind, True), noun


def rand_uuid(r: random.Random) -> str:
    h = pick(r, HEX, 32)
    return f"{h[:8]}-{h[8:12]}-4{h[13:16]}-{r.choice('89ab')}{h[17:20]}-{h[20:]}"


def private_key(r: random.Random, escaped: bool = False) -> list[Piece]:
    """A PEM private key; the BEGIN line and first line of key data are labeled."""
    label, head = r.choice([
        ("RSA PRIVATE KEY", "MIIEowIBAAKCAQEA"), ("RSA PRIVATE KEY", "MIIEpAIBAAKCAQEA"),
        ("PRIVATE KEY", "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC"), ("PRIVATE KEY", "MIIEvgIBADANBgkqhkiG9w0BAQEFAASC"),
        ("EC PRIVATE KEY", "MHcCAQEEI"), ("OPENSSH PRIVATE KEY", "b3BlbnNzaC1rZXktdjEAAAAA"),
        ("ENCRYPTED PRIVATE KEY", "MIIFHzBJBgkqhkiG9w0BBQ0wPDAbBgkqhkiG9w0BBQwwDgQI"),
        ("DSA PRIVATE KEY", "MIIBuwIBAAKBgQ"),
    ])
    n_bytes = {"EC PRIVATE KEY": 121, "OPENSSH PRIVATE KEY": r.choice([300, 1700])}.get(label, r.choice([600, 1200]))
    width = 70 if label == "OPENSSH PRIVATE KEY" else 64
    body = head + b64(r, n_bytes)
    lines = [body[i:i + width] for i in range(0, len(body), width)]
    nl = "\\n" if escaped else "\n"
    pieces: list[Piece] = [Val(f"-----BEGIN {label}-----{nl}{lines[0]}", "private_key", True)]
    rest = nl + nl.join(lines[1:]) + f"{nl}-----END {label}-----"
    pieces.append(rest)
    return pieces


# ---------------------------------------------------------------------------------------------
# Decoys: random-looking or secret-adjacent text that is not a secret.

def public_pem(r: random.Random, escaped: bool = False) -> str:
    label, head, n = r.choice([
        ("PUBLIC KEY", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA", 270),
        ("RSA PUBLIC KEY", "MIIBCgKCAQEA", 260), ("CERTIFICATE", "MIID", r.choice([700, 1000])),
        ("CERTIFICATE", "MIIF", 1300), ("PGP PUBLIC KEY BLOCK", "mQINBG", 1100),
        ("CERTIFICATE REQUEST", "MIIC", 600), ("PUBLIC KEY", "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE", 50),
    ])
    body = head + b64(r, n)
    nl = "\\n" if escaped else "\n"
    lines = nl.join(body[i:i + 64] for i in range(0, len(body), 64))
    extra = f"{nl}Version: GnuPG v2{nl}" if "PGP" in label and r.random() < 0.5 else nl
    return f"-----BEGIN {label}-----{extra}{lines}{nl}-----END {label}-----"


def ssh_public_key(r: random.Random) -> str:
    kind, head, n = r.choice([("ssh-rsa", "AAAAB3NzaC1yc2EAAAADAQABAAABgQ", 380),
                              ("ssh-ed25519", "AAAAC3NzaC1lZDI1NTE5AAAAI", 24),
                              ("ecdsa-sha2-nistp256", "AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBB", 48)])
    comment = r.choice(["", f" {r.choice(USERS)}@{r.choice(['laptop', 'build-01', 'ci', 'mbp.local'])}"])
    return f"{kind} {head}{b64(r, n)}{comment}"


def image_data(r: random.Random) -> str:
    mime, head = r.choice([("image/png", "iVBORw0KGgoAAAANSUhEUgAA"), ("image/jpeg", "/9j/4AAQSkZJRgABAQ"),
                           ("image/gif", "R0lGODlh"), ("image/webp", "UklGR"), ("font/woff2", "d09GMgABAAAAA"),
                           ("image/svg+xml", "PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmci")])
    return f"data:{mime};base64,{head}{b64(r, r.randint(40, 700))}"


def minified(r: random.Random) -> str:
    ids = [pick(r, string.ascii_letters + "_$", r.randint(1, 2)) for _ in range(12)]
    parts = []
    for _ in range(r.randint(4, 14)):
        a, b, c = r.sample(ids, 3)
        parts.append(r.choice([
            f"function {a}({b},{c}){{return {b}&&{c}.{r.choice(['length', 'push', 'map', 'call'])}({a})}}",
            f"var {a}={b}({c}),{b}={r.randint(0, 255)};",
            f"{a}.prototype.{r.choice(['init', 'render', 'get', 'set'])}=function({b}){{this.{c}={b}}};",
            f"if(!{a})throw new Error(\"{r.choice(PROSE_WORDS)}\");",
            f"{a}=\"{pick(r, LOWER_ALNUM, r.randint(3, 10))}\"+{b};",
            f"for(var {a}=0;{a}<{b}.length;{a}++){c}[{a}]^={b}[{a}];",
            f"{a}[\"{pick(r, HEX, 8)}\"]={{exports:{{}}}};",
            f"return{a}?{b}:{c}}}",
        ]))
    return "".join(parts)


def url(r: random.Random) -> str:
    host = r.choice(["www.example.com", "docs.acme.io", "cdn.jsdelivr.net", "github.com", "s3.amazonaws.com",
                     "storage.googleapis.com", "app.contoso.com", "fonts.gstatic.com", "youtube.com"])
    path = "/".join(r.choice([r.choice(PROSE_WORDS), pick(r, LOWER_ALNUM, r.randint(4, 12)), str(r.randint(1, 99999)),
                              rand_uuid(r)]) for _ in range(r.randint(1, 4)))
    query = "&".join(f"{k}={v}" for k, v in r.sample([
        ("utm_source", "newsletter"), ("utm_medium", "email"), ("page", str(r.randint(1, 50))),
        ("q", r.choice(PROSE_WORDS)), ("v", pick(r, URLSAFE, 11)), ("ref", pick(r, HEX, 7)),
        ("id", str(r.randint(1, 10**8))), ("lang", "en"), ("sort", "desc"), ("w", "1200"),
        ("fbclid", pick(r, URLSAFE, 30)), ("gclid", pick(r, URLSAFE, 40))], r.randint(0, 3)))
    return f"https://{host}/{path}" + (f"?{query}" if query else "")


PLACEHOLDERS = [
    "your_api_key_here", "YOUR_API_KEY", "<YOUR_API_KEY>", "<your-token>", "YOUR_TOKEN_HERE",
    "your-secret-key", "<api-key>", "INSERT_KEY_HERE", "REPLACE_ME", "replace-with-your-token",
    "changeme", "change-me", "CHANGEME", "password", "secret", "<password>", "your_password",
    "********", "****", "xxxxxxxx", "xxxxxxxxxxxxxxxxxxxxxxxx", "XXXXXXXXXXXXXXXXXXXX", "REDACTED",
    "[REDACTED]", "<redacted>", "***REDACTED***", "TODO", "todo-set-me", "dummy", "test", "example",
    "example-token", "foo", "foobar", "null", "none", "", "...", "abc123", "1234567890",
    "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "my-secret", "s3cr3t",
    "sk_test_xxxxxxxxxxxxxxxxxxxx", "<insert token>", "{token}", "%s", "TOKEN", "API_KEY",
    "secret-goes-here", "not-a-real-key", "fake-token-for-tests", "my_password", "hunter2",
]


def placeholder(r: random.Random) -> str:
    roll = r.random()
    if roll < 0.75:
        return r.choice(PLACEHOLDERS)
    if roll < 0.85:
        prefix = r.choice(["ghp_", "sk_live_", "AKIA", "xoxb-", "glpat-", "sk-", "npm_", ""])
        return prefix + r.choice("xX*0.") * r.randint(16, 40)
    if roll < 0.92:
        return r.choice(["sk-", "ghp_", "key_", ""]) + r.choice(["...", "…", "****"]) + pick(r, ALNUM, 4)
    return r.choice(["your", "my", "the", "a"]) + r.choice(["_", "-"]) + r.choice(SERVICES) + r.choice(["_", "-"]) + r.choice(
        ["api_key", "token", "secret", "password", "key"])


def env_reference(r: random.Random, style: str = "any") -> str:
    name = secret_name(r, r.choice(list(SECRET_NOUNS)), "upper")
    return r.choice([
        f"${{{name}}}", f"${name}", f"{{{{ secrets.{name} }}}}", f"{{{{ .Values.{styled(r, split_words(name.lower()), 'camel')} }}}}",
        f"%({name.lower()})s", f"${{env:{name}}}", f"#{{ENV['{name}']}}", f"{{{{ vault \"secret/data/{r.choice(SERVICES)}\" }}}}",
        f"vault:secret/data/{r.choice(SERVICES)}#{name.lower()}", f"arn:aws:secretsmanager:us-east-1:{pick(r, DIGITS, 12)}:secret:{r.choice(SERVICES)}-{pick(r, ALNUM, 6)}",
        f"{{{{resolve:secretsmanager:{r.choice(SERVICES)}/{name.lower()}}}}}", f"projects/{r.choice(WORDS)}-{r.randint(100, 999)}/secrets/{name.lower()}/versions/latest",
        f"<%= ENV['{name}'] %>", f"@Microsoft.KeyVault(SecretUri=https://{r.choice(WORDS)}.vault.azure.net/secrets/{name.lower()})",
    ])


def code_reference(r: random.Random, lang: str) -> str:
    name = secret_name(r, r.choice(list(SECRET_NOUNS)), "upper")
    return {
        "python": r.choice([f'os.environ["{name}"]', f'os.getenv("{name}")', f'settings.{name}',
                            f'config.get("{name.lower()}")', f'get_secret("{name.lower()}")']),
        "js": r.choice([f"process.env.{name}", f"process.env['{name}']", f"config.{styled(r, split_words(name.lower()), 'camel')}",
                        f"await getSecret('{name.lower()}')", f"import.meta.env.VITE_{name}"]),
        "go": r.choice([f'os.Getenv("{name}")', f'cfg.{styled(r, split_words(name.lower()), "pascal")}', f'viper.GetString("{name.lower()}")']),
        "java": r.choice([f'System.getenv("{name}")', f'env.getProperty("{name.lower().replace("_", ".")}")', f'config.get{styled(r, split_words(name.lower()), "pascal")}()']),
        "ruby": r.choice([f"ENV['{name}']", f"ENV.fetch('{name}')", f"Rails.application.credentials.{name.lower()}"]),
        "php": r.choice([f"getenv('{name}')", f"$_ENV['{name}']", f"env('{name}')", f"config('services.{name.lower()}')"]),
    }.get(lang, f"${{{name}}}")


def decoy_named(r: random.Random) -> tuple[Val, list[str]]:
    """A decoy and words for a name that suits it."""
    kind = r.choices(
        ["uuid", "git_sha", "sha256", "md5", "sha1", "sri", "image_data", "url", "placeholder",
         "env_reference", "prefixed_id", "cloud_id", "build_hash", "cursor", "fingerprint",
         "secret_named_setting", "lookup_key", "public_key_inline", "phone_or_number", "nanoid"],
        weights=[4, 3, 3, 2, 1, 2, 1, 2, 9, 5, 2, 2, 2, 1, 1, 4, 2, 1, 1, 1])[0]
    if kind == "uuid":
        return Val(rand_uuid(r), kind, False), r.choice([["id"], ["request", "id"], ["trace", "id"], ["tenant", "id"],
                                                         ["correlation", "id"], ["uuid"], ["account", "id"], ["device", "id"],
                                                         ["installation", "id"], ["subscription", "id"], ["project", "id"]])
    if kind == "git_sha":
        return Val(pick(r, HEX, r.choice([7, 8, 12, 40, 40])), kind, False), r.choice([["commit"], ["sha"], ["rev"], ["revision"],
                                                                                  ["git", "sha"], ["ref"], ["build", "commit"], ["head"]])
    if kind == "sha256":
        return Val(pick(r, HEX, 64), kind, False), r.choice([["sha256"], ["checksum"], ["digest"], ["hash"], ["content", "hash"],
                                                             ["sha256sum"], ["file", "hash"], ["blob", "sha"]])
    if kind == "md5":
        return Val(pick(r, HEX, 32), kind, False), r.choice([["md5"], ["etag"], ["checksum"], ["md5sum"], ["content", "md5"], ["hash"]])
    if kind == "sha1":
        return Val(pick(r, HEX, 40), kind, False), r.choice([["sha1"], ["checksum"], ["shasum"], ["object", "id"]])
    if kind == "sri":
        algo, n = r.choice([("sha256", 32), ("sha384", 48), ("sha512", 64)])
        return Val(f"{algo}-{b64(r, n)}", kind, False), [r.choice(["integrity", "hash", "sri"])]
    if kind == "image_data":
        return Val(image_data(r), kind, False), r.choice([["avatar"], ["logo"], ["icon"], ["image"], ["thumbnail"], ["src"]])
    if kind == "url":
        return Val(url(r), kind, False), r.choice([["url"], ["homepage"], ["docs", "url"], ["callback", "url"], ["href"], ["link"]])
    if kind == "placeholder":
        noun = r.choice(list(SECRET_NOUNS))
        return Val(placeholder(r), kind, False), split_words(r.choice(SECRET_NOUNS[noun]))
    if kind == "env_reference":
        noun = r.choice(list(SECRET_NOUNS))
        return Val(env_reference(r), kind, False), split_words(r.choice(SECRET_NOUNS[noun]))
    if kind == "prefixed_id":
        value = r.choice(["cus_", "pi_", "ch_", "price_", "prod_", "evt_", "sub_", "in_", "acct_", "txn_", "ord_", "usr_"]) + pick(r, ALNUM, r.randint(14, 24))
        return Val(value, kind, False), r.choice([["customer", "id"], ["payment", "intent"], ["charge", "id"], ["price", "id"],
                                                  ["product"], ["event", "id"], ["subscription"], ["invoice"], ["account"], ["order", "id"]])
    if kind == "cloud_id":
        value = r.choice([
            lambda: r.choice(["i-0", "ami-0", "sg-0", "vpc-0", "subnet-0", "vol-0", "eni-0", "snap-0"]) + pick(r, HEX, 16),
            lambda: f"arn:aws:{r.choice(['iam', 's3', 'lambda', 'sqs'])}::{pick(r, DIGITS, 12)}:{r.choice(['role', 'function', 'user'])}/{r.choice(WORDS)}-{r.choice(WORDS)}",
            lambda: pick(r, DIGITS, 12),
            lambda: f"{r.choice(WORDS)}-{r.choice(WORDS)}-{r.randint(100000, 999999)}",
            lambda: f"/subscriptions/{rand_uuid(r)}/resourceGroups/{r.choice(WORDS)}-rg",
        ])()
        return Val(value, kind, False), r.choice([["instance", "id"], ["ami"], ["security", "group"], ["vpc", "id"], ["role", "arn"],
                                                  ["account", "id"], ["project", "id"], ["resource", "id"]])
    if kind == "build_hash":
        value = r.choice([
            lambda: f"main.{pick(r, HEX, 8)}.js", lambda: f"app.{pick(r, HEX, 20)}.chunk.css", lambda: f"css-{pick(r, LOWER_ALNUM, 7)}",
            lambda: f"{r.choice(WORDS)}-{pick(r, HEX, 10)}-{pick(r, LOWER_ALNUM, 5)}", lambda: f"v{r.randint(1, 9)}.{r.randint(0, 40)}.{r.randint(0, 9)}+{pick(r, HEX, 7)}",
            lambda: f"sha256:{pick(r, HEX, 64)}", lambda: f"{pick(r, LOWER_ALNUM, 10)}.{pick(r, HEX, 8)}.woff2",
        ])()
        return Val(value, kind, False), r.choice([["bundle"], ["asset"], ["image", "digest"], ["class", "name"], ["build"], ["file"]])
    if kind == "cursor":
        value = base64.b64encode(json.dumps({"id": r.randint(1, 10**6), "ts": r.randint(1_500_000_000, 1_800_000_000)}).encode()).decode()
        return Val(value, kind, False), r.choice([["cursor"], ["next", "cursor"], ["page", "token"], ["continuation"], ["next", "page"]])
    if kind == "fingerprint":
        value = r.choice([lambda: "SHA256:" + b64(r, 32, pad=False), lambda: ":".join(pick(r, HEX, 2) for _ in range(16)),
                          lambda: " ".join(pick(r, HEX.upper(), 4) for _ in range(10))])()
        return Val(value, kind, False), r.choice([["fingerprint"], ["host", "key"], ["key", "fingerprint"], ["gpg", "key", "id"]])
    if kind == "secret_named_setting":
        words, value = r.choice([
            (["password", "min", "length"], str(r.randint(8, 16))), (["token", "type"], r.choice(["bearer", "Bearer", "jwt", "opaque"])),
            (["secret", "name"], f"{r.choice(SERVICES)}-{r.choice(['creds', 'credentials', 'secret', 'tls'])}"),
            (["api", "key", "header"], r.choice(["X-API-Key", "Authorization", "X-Auth-Token"])),
            (["token", "expiry"], str(r.choice([300, 3600, 86400]))), (["password", "hash"], r.choice(["argon2id", "bcrypt", "pbkdf2_sha256"])),
            (["auth", "method"], r.choice(["oauth2", "basic", "token", "none", "saml"])), (["key", "id"], f"{r.choice(SERVICES)}-{r.randint(1, 9)}"),
            (["secret", "path"], f"secret/data/{r.choice(SERVICES)}/{r.choice(['db', 'api', 'smtp'])}"),
            (["token", "url"], f"https://{r.choice(['auth', 'login', 'oauth2'])}.{r.choice(['acme', 'example'])}.com/oauth/token"),
            (["password", "reset", "ttl"], f"{r.randint(1, 48)}h"), (["key", "rotation", "days"], str(r.choice([30, 90, 180]))),
            (["credentials", "file"], r.choice(["~/.aws/credentials", "/etc/app/creds.json", "./secrets/service-account.json"])),
            (["key", "algorithm"], r.choice(["RS256", "HS256", "ES256", "AES-256-GCM"])), (["token", "audience"], f"api://{r.choice(SERVICES)}"),
        ])
        return Val(value, kind, False), words
    if kind == "lookup_key":
        value = r.choice([
            lambda: ".".join(r.choice(["user", "profile", "settings", "errors", "nav", "billing"]) for _ in range(r.randint(2, 4))),
            lambda: f"uploads/{r.randint(2019, 2026)}/{r.randint(1, 12):02d}/{pick(r, LOWER_ALNUM, 12)}.{r.choice(['png', 'pdf', 'csv'])}",
            lambda: f"{r.choice(['user', 'session', 'rate'])}:{r.randint(1, 99999)}:{r.choice(['profile', 'limit', 'cart'])}",
            lambda: f"{r.choice(WORDS)}_{r.choice(WORDS)}",
        ])()
        return Val(value, kind, False), r.choice([["key"], ["cache", "key"], ["object", "key"], ["i18n", "key"], ["s3", "key"], ["partition", "key"]])
    if kind == "public_key_inline":
        return Val(ssh_public_key(r), kind, False), r.choice([["public", "key"], ["ssh", "key"], ["authorized", "key"], ["pubkey"]])
    if kind == "phone_or_number":
        value = r.choice([lambda: f"+1{pick(r, DIGITS, 10)}", lambda: pick(r, DIGITS, r.randint(10, 20)), lambda: f"{r.randint(1, 9)}{pick(r, DIGITS, 17)}"])()
        return Val(value, kind, False), r.choice([["phone"], ["order", "number"], ["discord", "id"], ["timestamp"], ["snowflake"]])
    value = pick(r, URLSAFE, 21)
    return Val(value, kind, False), r.choice([["build", "id"], ["short", "id"], ["slug"], ["nonce", "seed"], ["public", "id"]])


def secret_named(r: random.Random) -> tuple[list[Piece], list[str]]:
    """A secret and words for a name to keep it under. Shape-recognizable formats sometimes sit
    under a bland name, since the format alone gives them away."""
    if r.random() < 0.04:
        return private_key(r, escaped=True), ["private", "key"]
    if r.random() < 0.08:
        return connection_string(r), split_words(r.choice(SECRET_NOUNS["credential"]))
    if r.random() < 0.05:
        return webhook_url(r), r.choice([["webhook", "url"], ["slack", "webhook"], ["hook"], ["notify", "url"], ["webhook"], ["discord", "webhook", "url"]])
    value, noun = make_secret(r)
    if value.kind in SHAPED and r.random() < 0.15:
        words = split_words(plain_name(r, "snake")) if r.random() < 0.5 else [r.choice(["value", "data", "x", "config", "setting"])]
    else:
        words = split_words(r.choice(SECRET_NOUNS[noun]))
        if r.random() < 0.5:
            words = split_words(r.choice(SERVICES)) + words
    return [value], words


def connection_string(r: random.Random) -> list[Piece]:
    pw = Val(r.choice([human_password, random_password])(r), "connection_password", True)
    user, host = r.choice(USERS), r.choice(HOSTS)
    db = r.choice(["app", "prod", "orders", "analytics", "main", "users"])
    return r.choice([
        lambda: [f"{r.choice(['postgres', 'postgresql', 'mysql', 'mariadb', 'mssql'])}://{user}:", pw, f"@{host}:{r.choice([5432, 3306, 1433])}/{db}" + r.choice(["", "?sslmode=require", "?ssl=true"])],
        lambda: ["mongodb+srv://", user, ":", pw, f"@cluster0.{pick(r, LOWER_ALNUM, 5)}.mongodb.net/{db}?retryWrites=true&w=majority"],
        lambda: [f"redis://{r.choice(['', 'default'])}:", pw, f"@{host}:6379/0"],
        lambda: [f"amqp://{user}:", pw, f"@{host}:5672/{r.choice(['', 'vhost'])}"],
        lambda: [f"Server=tcp:{r.choice(WORDS)}.database.windows.net,1433;Database={db};User ID={user};Password=", pw, ";Encrypt=True;"],
        lambda: [f"Host={host};Port=5432;Database={db};Username={user};Password=", pw],
        lambda: [f"jdbc:postgresql://{host}:5432/{db}?user={user}&password=", pw],
        lambda: [f"DefaultEndpointsProtocol=https;AccountName={r.choice(WORDS)}{r.randint(1, 99)};AccountKey=",
                 Val(b64(r, 64), "azure_storage_key", True), ";EndpointSuffix=core.windows.net"],
        lambda: [f"https://{user}:", pw, f"@{r.choice(['git.acme.io', 'registry.corp.local', 'nexus.internal', 'github.com'])}/{r.choice(WORDS)}"],
        lambda: [f"smtp://{user}%40{r.choice(['acme.com', 'gmail.com'])}:", pw, f"@{r.choice(['smtp.gmail.com', 'smtp.sendgrid.net'])}:587"],
    ])()


def url_with_secret(r: random.Random) -> list[Piece]:
    """A URL that carries a credential in its query string: a signature or token, sometimes
    percent-encoded the way a browser or SDK writes it."""
    raw = r.choice([lambda: b64(r, 32), lambda: make_secret(r)[0].text, lambda: pick(r, HEX, 64)])()
    secret = raw.replace("+", "%2B").replace("/", "%2F").replace("=", "%3D") if r.random() < 0.6 else raw
    name = r.choice(["sig", "signature", "token", "access_token", "api_key", "key", "apikey", "auth", "X-Amz-Signature", "client_secret", "code_secret"])
    before = "&".join(f"{k}={v}" for k, v in r.sample([
        ("sv", "2022-11-02"), ("ss", "b"), ("srt", "co"), ("sp", r.choice(["r", "rl", "rwdl"])), ("se", "2026-12-01T00:00:00Z"),
        ("X-Amz-Algorithm", "AWS4-HMAC-SHA256"), ("X-Amz-Expires", "3600"), ("format", "json"), ("limit", "100"), ("v", "2")], r.randint(1, 4)))
    host = r.choice(["acme.blob.core.windows.net/backups/db.sql", "api.acme.io/v2/export", "s3.amazonaws.com/acme-logs/app.log.gz",
                     "maps.example.com/api/geocode", "hooks.acme.dev/ingest", "storage.example.net/f/report.pdf"])
    return [f"https://{host}?{before}&{name}=", Val(secret, "url_secret", True), r.choice(["", "", f"&page={r.randint(1, 9)}", "&spr=https"])]


def call_secret(r: random.Random, lang: str) -> list[Piece]:
    """A credential passed straight to a function, with no name of its own: a client
    constructor, a connect or login call, an auth tuple."""
    token, _ = make_secret(r, ["generic_alnum", "generic_hex", "novel_prefixed", "composite_token", "generic_base64",
                               "github_token", "stripe_key", "llm_api_key", "slack_token", "jwt"])
    pw = Val(r.choice([human_password, random_password])(r), "password", True)
    user, host = r.choice(USERS), r.choice(HOSTS)
    q = '"' if lang in ("go", "java", "csharp") or r.random() < 0.5 else "'"
    lib = r.choice(["cohere", "telebot", "pusher", "mapbox", "weather", "geo", "acme_sdk", "crm", "sms", "mailer", "analytics"])
    cls = r.choice(["Client", "TeleBot", "Bot", "Api", "Session", "Service", "Connector", "Sdk"])
    end = ";" if lang in ("js", "java", "php", "csharp") else ""
    options = [
        lambda: [f"client = {lib}.{cls}({q}", token, f"{q})"],
        lambda: [f"{ident(r, 'camel')} = new {ident(r, 'pascal')}{cls}({q}", token, f"{q}){end}"],
        lambda: [f"{r.choice(['conn', 'db', 'cnx'])} = {r.choice(['psycopg2.connect', 'pymysql.connect', 'connect', 'mysqli_connect', 'Connect'])}({q}{host}{q}, {q}{user}{q}, {q}", pw, f"{q}{r.choice(['', ', ' + q + 'app' + q])}){end}"],
        lambda: [f"Connection c = DriverManager.getConnection({q}jdbc:{r.choice(['mysql', 'postgresql'])}://{host}/{r.choice(['shop', 'app'])}{q}, {q}{user}{q}, {q}", pw, f"{q});"],
        lambda: [f"r = requests.get(url, auth=({q}{user}{q}, {q}", pw, f"{q}))"],
        lambda: [f"auth = HTTPBasicAuth({q}{user}{q}, {q}", pw, f"{q})"],
        lambda: [f"var cred = new NetworkCredential({q}{user}{q}, {q}", pw, f"{q});"],
        lambda: [f"{r.choice(['ds', 'factory', 'cfg'])}.setPassword({q}", pw, f"{q}){end}"],
        lambda: [f"await {r.choice(['client', 'api', 'sdk'])}.{r.choice(['login', 'authenticate', 'auth', 'connect'])}({q}{user}{q}, {q}", pw, f"{q}){end}"],
        lambda: [f"{r.choice(['stripe', 'sdk', 'api'])} = require({q}{lib}{q})({q}", token, f"{q}){end}"],
        lambda: [f"headers = {{{q}Authorization{q}: {q}Bearer ", token, f"{q}}}"],
        lambda: [f"req.Header.Set({q}{r.choice(['X-API-Key', 'X-Auth-Token', 'Authorization', 'Api-Key'])}{q}, {q}", token, f"{q})"],
        lambda: [f"{ident(r)}.{r.choice(['set_api_key', 'configure', 'init', 'setToken', 'useKey'])}({q}", token, f"{q}){end}"],
        lambda: [f"$securePassword = ConvertTo-SecureString \"", pw, "\" -AsPlainText -Force"],
        lambda: [f"{r.choice(['New-LocalUser', 'Set-ADAccountPassword', 'Connect-Server', 'Invoke-Deploy'])} -{r.choice(['Password', 'Token', 'ApiKey', 'Secret'])} \"", pw, "\""],
        lambda: [f"{r.choice(['slackSend', 'notify', 'post_message', 'send'])}({r.choice(['webhookUrl: ', 'url=', ''])}{q}", webhook_url(r), f"{q}, {r.choice(['message', 'text'])}: {q}{comment_text(r)}{q})"],
        lambda: [f"define( {q}{r.choice(['AUTH_KEY', 'SECURE_AUTH_KEY', 'LOGGED_IN_KEY', 'NONCE_KEY', 'AUTH_SALT', 'SECURE_AUTH_SALT', 'LOGGED_IN_SALT', 'NONCE_SALT'])}{q}, {q}", Val(salt(r), "salt", True), f"{q} );"],
    ]
    return r.choice(options)()


def call_decoy(r: random.Random, lang: str) -> list[Piece]:
    """The same calls with nothing secret in the arguments."""
    q = '"' if r.random() < 0.5 else "'"
    user, host = r.choice(USERS), r.choice(HOSTS)
    ref = Val(code_reference(r, lang), "code_reference", False)
    return r.choice([
        lambda: [f"client = {r.choice(['cohere', 'acme_sdk', 'crm'])}.Client(", ref, ")"],
        lambda: [f"conn = connect({q}{host}{q}, {q}{user}{q}, ", ref, ")"],
        lambda: [f"conn = connect({q}{host}{q}, {q}{user}{q}, password)"],
        lambda: [f"r = requests.get(url, auth=({q}{user}{q}, ", Val(r.choice(["password", "self.password", "getpass.getpass()"]), "code_reference", False), "))"],
        lambda: [f"client = Client({q}", Val(placeholder(r), "placeholder", False), f"{q})"],
        lambda: [f"req.Header.Set({q}X-Request-Id{q}, {q}", Val(rand_uuid(r), "uuid", False), f"{q})"],
        lambda: [f"cache.get({q}", Val(pick(r, HEX, 40), "sha1", False), f"{q})"],
        lambda: [f"user = User.find({q}", Val(r.choice([rand_uuid(r), "usr_" + pick(r, ALNUM, 16)]), "prefixed_id", False), f"{q})"],
        lambda: [f"verify({q}", Val(pick(r, HEX, 64), "sha256", False), f"{q}, data)"],
    ])()


# ---------------------------------------------------------------------------------------------
# Ordinary lines for each kind of document.

def comment_text(r: random.Random) -> str:
    words = [r.choice(PROSE_WORDS) for _ in range(r.randint(3, 12))]
    if r.random() < 0.15:
        words.insert(r.randint(0, len(words)), r.choice(UNICODE_BITS))
    text = " ".join(words)
    return text[0].upper() + text[1:]


def sentence(r: random.Random) -> str:
    return comment_text(r) + r.choice([".", ".", "?", "!", ":", "..."])


def ident(r: random.Random, style: str = "snake") -> str:
    return styled(r, [r.choice(PROSE_WORDS) for _ in range(r.randint(1, 3))], style)


def log_prefix(r: random.Random) -> str:
    ts = f"2026-{r.randint(1, 12):02d}-{r.randint(1, 28):02d}{r.choice(['T', ' '])}{r.randint(0, 23):02d}:{r.randint(0, 59):02d}:{r.randint(0, 59):02d}{r.choice(['Z', '.123Z', ',441', ''])}"
    level = r.choice(["INFO", "DEBUG", "WARN", "ERROR", "info", "level=info", "I"])
    svc = r.choice(["api", "worker", "auth", "gateway", "billing", "scheduler"])
    return r.choice([f"{ts} {level} [{svc}] ", f"[{ts}] {level}: ", f"{ts} {svc}[{r.randint(100, 9999)}]: {level} ", f"{level} {ts} "])


def log_filler(r: random.Random) -> list[Piece]:
    return r.choice([
        lambda: [f"{r.choice(['GET', 'POST', 'PUT', 'DELETE'])} /{r.choice(['api', 'v1', 'health'])}/{ident(r)} {r.choice([200, 201, 204, 301, 400, 404, 500])} {r.randint(1, 900)}ms"],
        lambda: [comment_text(r)],
        lambda: ["request_id=", Val(rand_uuid(r), "uuid", False), f" user={r.randint(1, 99999)} duration={r.random():.3f}s"],
        lambda: [f"connected to {r.choice(HOSTS)} in {r.randint(1, 500)}ms"],
        lambda: ["trace=", Val(pick(r, HEX, 32), "trace_id", False), " span=", Val(pick(r, HEX, 16), "span_id", False), f" {comment_text(r)}"],
        lambda: [f"job {r.choice(WORDS)} finished: {r.randint(0, 9999)} rows, {r.randint(0, 9)} errors"],
        lambda: [f"client {r.randint(1, 255)}.{r.randint(0, 255)}.{r.randint(0, 255)}.{r.randint(0, 255)} - \"{r.choice(['GET', 'POST'])} ", Val(url(r), "url", False), "\""],
        lambda: ["deployed ", Val(pick(r, HEX, 40), "git_sha", False), f" to {r.choice(['prod', 'staging'])}"],
        lambda: [f"cache miss for key {r.choice(['user', 'session', 'cart'])}:{r.randint(1, 99999)}"],
        lambda: [f"Traceback (most recent call last): File \"/app/{ident(r)}.py\", line {r.randint(1, 900)}"],
    ])()


def code_filler(r: random.Random, lang: str) -> str:
    a, b, c = ident(r), ident(r), ident(r)
    ca, cb = ident(r, "camel"), ident(r, "camel")
    pa = ident(r, "pascal")
    options = {
        "python": [f"import {r.choice(['os', 'json', 'logging', 'requests', 'boto3', 'hashlib'])}", f"def {a}({b}, {c}=None):",
                   f"    return {b}.get(\"{c}\")", f"    for {b} in {c}:", f"        logger.info(\"{comment_text(r)}\")",
                   f"class {pa}:", f"    {a} = {r.randint(0, 100)}", f"if __name__ == \"__main__\":", f"    {a}.{b}({c})",
                   f"# {comment_text(r)}", f"{a} = {b}({c}, timeout={r.randint(1, 60)})", "", f"    raise ValueError(\"{comment_text(r)}\")"],
        "js": [f"import {{ {ca} }} from '{r.choice(['./util', 'react', 'axios', '../lib/' + a])}';", f"const {ca} = require('{r.choice(['express', 'fs', 'path'])}');",
               f"export function {ca}({cb}) {{", f"  return {cb}.{r.choice(['map', 'filter', 'then'])}((x) => x.{ca});", "}", f"// {comment_text(r)}",
               f"  if (!{cb}) throw new Error('{comment_text(r)}');", f"app.use({ca}());", f"const {ca} = await fetch(`/api/${{{cb}}}`);", ""],
        "go": [f"func {pa}({cb} string) error {{", f"\t{ca}, err := {cb}.{pa}()", "\tif err != nil {", "\t\treturn err", "\t}", "}",
               f"// {comment_text(r)}", f"import \"{r.choice(['fmt', 'os', 'net/http', 'context'])}\"", f"\tlog.Printf(\"{comment_text(r)}: %v\", {ca})", ""],
        "java": [f"public class {pa} {{", f"    private final {pa} {ca};", f"    public void {ca}(String {cb}) {{", "    }", "}",
                 f"        log.info(\"{comment_text(r)}\");", f"// {comment_text(r)}", f"import java.util.{r.choice(['List', 'Map', 'Optional'])};", ""],
        "ruby": [f"class {pa} < ApplicationRecord", f"  def {a}", "  end", "end", f"  has_many :{a}", f"# {comment_text(r)}",
                 f"  validates :{a}, presence: true", f"require '{r.choice(['json', 'net/http', 'yaml'])}'", ""],
        "php": ["<?php", f"function {ca}(${cb}) {{", f"    return ${cb}['{a}'];", "}", f"// {comment_text(r)}", f"use App\\{pa};",
                f"${ca} = new {pa}();", ""],
        "csharp": [f"public class {pa}", "{", "}", f"    public string {pa} {{ get; set; }}", f"// {comment_text(r)}",
                   f"using System.{r.choice(['Text', 'Linq', 'Net.Http'])};", f"    var {ca} = new {pa}();", ""],
    }
    return r.choice(options.get(lang, options["python"]))


# ---------------------------------------------------------------------------------------------
# How each kind of file writes a name and a value.

def assignment(r: random.Random, w: Writer, fmt: str, words: list[str], value: list[Piece], indent: str = "") -> None:
    q = r.choice(['"', "'"]) if fmt not in ("json", "go", "csharp", "java") else '"'
    if fmt == "env":
        name = styled(r, words, "upper" if r.random() < 0.85 else "snake")
        w.line(r.choice(["", "", "export "]), name, "=", *wrap(r, value, ["", '"', "'"]))
    elif fmt == "yaml":
        w.line(indent, styled(r, words, r.choice(["snake", "camel", "kebab", "upper"])), ": ", *wrap(r, value, ["", '"', "'"]))
    elif fmt == "json":
        w.line(indent, f'"{styled(r, words, r.choice(["camel", "snake", "pascal", "kebab"]))}": "', *value, '",')
    elif fmt in ("toml", "terraform"):
        w.line(indent, styled(r, words, "snake"), " = ", q, *value, q)
    elif fmt == "ini":
        w.line(styled(r, words, r.choice(["snake", "flat", "camel"])), r.choice(["=", " = ", ": "]), *value)
    elif fmt == "properties":
        w.line(".".join(words if r.random() < 0.5 else ["spring", "datasource"] + words[-1:]), "=", *value)
    elif fmt == "python":
        r.choice([
            lambda: w.line(styled(r, words, r.choice(["upper", "snake"])), " = ", q, *value, q),
            lambda: w.line(indent or "    ", styled(r, words, "snake"), "=", q, *value, q, ","),
            lambda: w.line(indent or "    ", q, styled(r, words, "snake"), q, ": ", q, *value, q, ","),
            lambda: w.line(f"client = {ident(r, 'pascal')}({styled(r, words, 'snake')}=", q, *value, q, ")"),
            lambda: w.line(f"os.environ.setdefault(\"{styled(r, words, 'upper')}\", ", q, *value, q, ")"),
        ])()
    elif fmt == "js":
        r.choice([
            lambda: w.line(r.choice(["const ", "let ", "var ", "export const "]), styled(r, words, r.choice(["camel", "upper"])), " = ", q, *value, q, ";"),
            lambda: w.line(indent or "  ", styled(r, words, "camel"), ": ", q, *value, q, ","),
            lambda: w.line(f"const client = new {ident(r, 'pascal')}({{ {styled(r, words, 'camel')}: ", q, *value, q, " });"),
            lambda: w.line(f"{r.choice(['config', 'options', 'this', 'process.env'])}.{styled(r, words, r.choice(['camel', 'upper']))} = ", q, *value, q, ";"),
        ])()
    elif fmt == "go":
        r.choice([
            lambda: w.line("\t", styled(r, words, "camel"), " := \"", *value, "\""),
            lambda: w.line("\t", styled(r, words, "pascal"), ": \"", *value, "\","),
            lambda: w.line("const ", styled(r, words, "pascal"), " = \"", *value, "\""),
        ])()
    elif fmt == "java":
        r.choice([
            lambda: w.line("    private static final String ", styled(r, words, "upper"), " = \"", *value, "\";"),
            lambda: w.line(f"        props.setProperty(\"{'.'.join(words)}\", \"", *value, "\");"),
            lambda: w.line("        String ", styled(r, words, "camel"), " = \"", *value, "\";"),
        ])()
    elif fmt == "ruby":
        r.choice([
            lambda: w.line(f"  config.{styled(r, words, 'snake')} = ", q, *value, q),
            lambda: w.line(indent or "  ", styled(r, words, "snake"), ": ", q, *value, q, ","),
        ])()
    elif fmt == "php":
        r.choice([
            lambda: w.line(indent or "    ", f"'{styled(r, words, 'snake')}' => ", q, *value, q, ","),
            lambda: w.line(f"${styled(r, words, 'camel')} = ", q, *value, q, ";"),
            lambda: w.line(f"define('{styled(r, words, 'upper')}', ", q, *value, q, ");"),
        ])()
    elif fmt == "csharp":
        r.choice([
            lambda: w.line(f"    options.{styled(r, words, 'pascal')} = \"", *value, "\";"),
            lambda: w.line(f"    private const string {styled(r, words, 'pascal')} = \"", *value, "\";"),
        ])()
    elif fmt == "shell":
        r.choice([
            lambda: w.line("export ", styled(r, words, "upper"), "=", *wrap(r, value, ['"', "'", ""])),
            lambda: w.line(f"{r.choice(['./deploy.sh', 'app', 'terraform apply', 'helm upgrade api ./chart', 'node server.js'])} --{styled(r, words, 'kebab')}", r.choice([" ", "="]), *wrap(r, value, ['"', "'", ""])),
            lambda: w.line(f"helm upgrade api ./chart --set {styled(r, words, 'camel')}=", *value),
        ])()
    elif fmt == "dockerfile":
        w.line(r.choice(["ENV ", "ARG "]), styled(r, words, "upper"), "=", *wrap(r, value, ["", '"']))
    elif fmt == "xml":
        r.choice([
            lambda: w.line(indent, f"<{styled(r, words, 'camel')}>", *value, f"</{styled(r, words, 'camel')}>"),
            lambda: w.line(indent, f"<add key=\"{styled(r, words, 'pascal')}\" value=\"", *value, "\" />"),
            lambda: w.line(indent, f"<property name=\"{'.'.join(words)}\" value=\"", *value, "\"/>"),
        ])()
    else:
        w.line(styled(r, words), "=", *value)


def wrap(r: random.Random, value: list[Piece], quotes: list[str]) -> list[Piece]:
    q = r.choice(quotes)
    return [q, *value, q]


# Secrets that appear in running text or commands rather than under a name.

def inline_secret(r: random.Random, fmt: str) -> list[Piece]:
    token, _ = make_secret(r, ["github_token", "jwt", "generic_alnum", "novel_prefixed", "llm_api_key", "slack_token",
                               "generic_base64", "gitlab_token", "generic_hex", "stripe_key", "google_api_key"])
    pw = Val(human_password(r) if r.random() < 0.6 else random_password(r), "password", True)
    user = r.choice(USERS)
    if fmt == "log":
        return r.choice([
            lambda: [log_prefix(r), "outgoing request headers: {'Authorization': 'Bearer ", token, "'}"],
            lambda: [log_prefix(r), f"POST /login body=username={user}&password=", pw],
            lambda: [log_prefix(r), "GET /api/v1/export?", r.choice(["api_key", "access_token", "token", "key"]), "=", token, f" 200 {r.randint(1, 900)}ms"],
            lambda: [log_prefix(r), "failed to connect: ", connection_string(r)],
            lambda: [log_prefix(r), "Authorization: ", r.choice(["Bearer ", "token ", "Token "]), token],
            lambda: [log_prefix(r), f"login ok user={user} pass=", pw],
            lambda: [log_prefix(r), f"GET ", url_with_secret(r), f" {r.choice([200, 403])}"],
        ])()
    if fmt == "prose":
        return r.choice([
            lambda: [r.choice(["Hey, ", "FYI ", "", "Heads up: "]), r.choice(["the staging key is ", "use this token: ", "here's the API key ", "token for the bot is "]), token, r.choice([" (rotate after the demo)", ", don't share", "", " - thanks!"])],
            lambda: [r.choice(["The password for ", "Password for ", "pw for "]), r.choice(["the admin account", "the VPN", "the shared mailbox", "prod db", "the wifi"]), r.choice([" is ", ": ", " = "]), pw],
            lambda: ["Login: ", f"{user} / ", pw],
            lambda: [r.choice(["You can test with `", "Run it with `", "Use `"]), "curl -H \"Authorization: Bearer ", token, f"\" https://api.{r.choice(['acme', 'example'])}.com/v1/me`"],
            lambda: [r.choice(["Credentials: ", "creds -> ", "Account: "]), f"{user}:", pw],
            lambda: [r.choice(["New key generated: ", "Key: ", "API key = ", "secret: "]), token],
            lambda: [r.choice(["Here's the download link: ", "Link (expires friday): ", "Shared it: "]), url_with_secret(r)],
            lambda: [r.choice(["They pasted their token (", "The leaked key ("]), token, r.choice([") into the ticket.", ") is in the screenshot."])],
        ])()
    # Shell and similar.
    return r.choice([
        lambda: ["curl -s -H \"Authorization: Bearer ", token, f"\" https://api.{r.choice(['acme', 'github', 'example'])}.com/{ident(r)}"],
        lambda: [f"curl -u {user}:", pw, f" https://{r.choice(HOSTS)}/api"],
        lambda: [f"curl -H 'X-Api-Key: ", token, "' https://api.example.com/v2/items"],
        lambda: [f"mysql -u {user} -p", pw, f" -h {r.choice(HOSTS)}"],
        lambda: [f"mysql -u {user} -p'", pw, "'"],
        lambda: [f"PGPASSWORD=", pw, f" psql -h {r.choice(HOSTS)} -U {user} {r.choice(['app', 'prod'])}"],
        lambda: [f"docker login -u {user} -p ", pw, f" {r.choice(['registry.acme.io', 'ghcr.io', ''])}"],
        lambda: ["sshpass -p '", pw, f"' ssh {user}@{r.choice(HOSTS)}"],
        lambda: [f"kubectl create secret generic {r.choice(SERVICES)} --from-literal=password=", pw],
        lambda: ["aws configure set aws_secret_access_key ", Val(pick(r, BASE64, 40), "aws_secret_key", True)],
        lambda: ["git clone https://", f"{user}:" if r.random() < 0.5 else "oauth2:", token, f"@github.com/{r.choice(WORDS)}/{r.choice(WORDS)}.git"],
        lambda: ["echo ", token, " | docker login ghcr.io -u ", user, " --password-stdin"],
        lambda: ["htpasswd -b -c .htpasswd ", user, " ", pw],
        lambda: [f"heroku config:set {secret_name(r, 'key', 'upper')}=", token],
        lambda: ["redis-cli -a ", pw, " ping"],
        lambda: [f"curl {r.choice(['--user', '-u'])} {r.choice(['', '"'])}{r.choice(['anystring', 'api', 'user', 'x', ''])}:", token, f"{r.choice(['', '"'])} https://api.{r.choice(['acme', 'example'])}.com/3.0/lists"],
        lambda: ["curl -u ", token, ": https://api.example.com/v1/charges"],
        lambda: ["curl '", url_with_secret(r), "'"],
        lambda: ["wget -O out.json \"", url_with_secret(r), "\""],
    ])()


def special_file(r: random.Random, w: Writer) -> None:
    """Credential files with formats of their own."""
    kind = r.random()
    if r.random() < 0.3:
        r.choice([
            lambda: [w.line(f"BUNDLE_{r.choice(['GEMS__CONTRIBSYS__COM', 'ENTERPRISE__CONTRIBSYS__COM', 'GEMS__GRAPHQL__PRO', 'RUBYGEMS__PKG__GITHUB__COM'])}: \"",
                            Val(r.choice([lambda: f"{pick(r, HEX, 8)}:{pick(r, HEX, 8)}", lambda: f"{r.choice(USERS)}:{make_secret(r)[0].text}"])(), "composite_token", True), "\"")
                     for _ in range(1)],
            lambda: [w.line(f"{r.choice(HOSTS)}:{r.choice([5432, '*'])}:{r.choice(['*', 'app', 'prod'])}:{r.choice(USERS)}:",
                            Val(r.choice([human_password, random_password])(r), "password", True)) for _ in range(r.randint(1, 3))],
            lambda: (w.line("[client]"), w.line(f"user={r.choice(USERS)}"), w.line("password=", Val(random_password(r), "password", True)), w.line(f"host={r.choice(HOSTS)}")),
            lambda: (w.put('{"auths": {"' + r.choice(["ghcr.io", "https://index.docker.io/v1/", "registry.acme.io"]) + '": {"auth": "'),
                     w.put(Val(base64.b64encode(f"{r.choice(USERS)}:{make_secret(r)[0].text}".encode()).decode(), "base64_secret", True)), w.line('"}}}')),
        ])()
        return
    if kind < 0.15:
        w.line(f"machine {r.choice(['api.heroku.com', 'github.com', 'git.acme.io'])}")
        w.line(f"  login {r.choice(USERS)}@acme.com")
        w.line("  password ", make_secret(r, ["github_token", "generic_hex", "uuid_secret", "password", "generic_alnum"])[0])
    elif kind < 0.3:
        w.line("//registry.npmjs.org/:_authToken=", make_secret(r, ["npm_token", "generic_alnum"])[0])
        w.line("registry=https://registry.npmjs.org/")
    elif kind < 0.45:
        w.line("[default]")
        w.line("aws_access_key_id = ", make_secret(r, ["aws_access_key"])[0])
        w.line("aws_secret_access_key = ", make_secret(r, ["aws_secret_key"])[0])
        w.line(f"region = {r.choice(['us-east-1', 'eu-west-1'])}")
    elif kind < 0.65:
        account = {"type": "service_account", "project_id": f"{r.choice(WORDS)}-{r.randint(100000, 999999)}"}
        w.line("{")
        w.line(f'  "type": "service_account",')
        w.line(f'  "project_id": "{account["project_id"]}",')
        w.line('  "private_key_id": "', Val(pick(r, HEX, 40), "private_key_id", True), '",')
        w.line('  "private_key": "', private_key(r, escaped=True), '\\n",')
        w.line(f'  "client_email": "{r.choice(WORDS)}@{account["project_id"]}.iam.gserviceaccount.com",')
        w.line(f'  "client_id": "{pick(r, DIGITS, 21)}",')
        w.line('  "token_uri": "https://oauth2.googleapis.com/token"')
        w.line("}")
    elif kind < 0.8:
        w.line("apiVersion: v1")
        w.line("kind: Secret")
        w.line("metadata:")
        w.line(f"  name: {r.choice(SERVICES)}-credentials")
        w.line("type: Opaque")
        w.line("data:")
        for _ in range(r.randint(1, 3)):
            if r.random() < 0.4:
                w.line(f"  {r.choice(['username', 'user', 'host'])}: {base64.b64encode(r.choice(USERS + HOSTS).encode()).decode()}")
            else:
                raw = (human_password(r) if r.random() < 0.5 else make_secret(r)[0].text).encode()
                w.line(f"  {styled(r, split_words(r.choice(SECRET_NOUNS[r.choice(['password', 'token', 'key'])])), 'snake')}: ",
                       Val(base64.b64encode(raw).decode(), "base64_secret", True))
    else:
        w.line(r.choice(["CREATE USER ", "CREATE ROLE "]), r.choice(USERS), r.choice([" WITH LOGIN PASSWORD '", " WITH PASSWORD '"]),
               Val(human_password(r), "password", True), "';")
        w.line(f"GRANT SELECT ON ALL TABLES IN SCHEMA public TO {r.choice(USERS)};")
        if r.random() < 0.5:
            w.line(f"ALTER USER '{r.choice(USERS)}'@'%' IDENTIFIED BY '", Val(random_password(r), "password", True), "';")


def decoy_block(r: random.Random, w: Writer, fmt: str) -> None:
    """Multi-line or structural decoys."""
    kind = r.random()
    if kind < 0.2:
        w.line(Val(public_pem(r), "public_pem", False))
    elif kind < 0.3:
        w.line(Val(ssh_public_key(r), "ssh_public_key", False))
    elif kind < 0.45:
        algo, n = r.choice([("sha384", 48), ("sha512", 64), ("sha256", 32)])
        w.line(f'<script src="https://cdn.jsdelivr.net/npm/{r.choice(WORDS)}@{r.randint(1, 9)}.{r.randint(0, 9)}.0/dist/x.min.js" integrity="',
               Val(f"{algo}-{b64(r, n)}", "sri", False), '" crossorigin="anonymous"></script>')
    elif kind < 0.55:
        w.line('<img alt="logo" src="', Val(image_data(r), "image_data", False), '">')
    elif kind < 0.65:
        w.line(Val(minified(r), "minified", False))
    elif kind < 0.75:
        name = r.choice(WORDS)
        w.line(f'    "node_modules/{name}": {{')
        w.line(f'      "version": "{r.randint(0, 9)}.{r.randint(0, 20)}.{r.randint(0, 9)}",')
        w.line(f'      "resolved": "https://registry.npmjs.org/{name}/-/{name}-1.0.0.tgz",')
        w.line('      "integrity": "', Val(f"sha512-{b64(r, 64)}", "sri", False), '"')
        w.line("    },")
    elif kind < 0.85:
        w.line(Val(pick(r, HEX, 64), "sha256", False), f"  {r.choice(WORDS)}-{r.randint(1, 9)}.{r.randint(0, 9)}.tar.gz")
        if r.random() < 0.5:
            w.line(f'checksum = "', Val(pick(r, HEX, 64), "sha256", False), '"')
        else:
            w.line(f"{r.choice(['github.com', 'golang.org/x'])}/{r.choice(WORDS)} v0.{r.randint(1, 20)}.0 h1:", Val(b64(r, 32), "go_sum", False))
    elif kind < 0.93:
        w.line("commit ", Val(pick(r, HEX, 40), "git_sha", False))
        w.line(f"Author: {r.choice(WORDS).capitalize()} <{r.choice(USERS)}@acme.com>")
        w.line(f"    {sentence(r)}")
    elif kind < 0.96:
        w.line(f"{r.choice(['docker pull', 'image:', 'FROM'])} {r.choice(['nginx', 'postgres', 'node'])}@", Val(f"sha256:{pick(r, HEX, 64)}", "sha256", False))
    else:
        w.line(*bare_digest(r))


def bare_digest(r: random.Random) -> list[Piece]:
    """A digest or hash with little around it to say what it is."""
    return r.choice([
        lambda: ["echo \"", Val(pick(r, HEX, 64), "sha256", False), f"  {r.choice(WORDS)}-{r.randint(1, 20)}.{r.randint(0, 9)}.tar.xz\" | sha256sum -c -"],
        lambda: [f"{r.choice(['tx', 'txid', 'hash', 'block'])} ", Val("0x" + pick(r, HEX, 64), "tx_hash", False), f" {r.choice(['confirmed', 'mined', 'pending', 'included'])} after {r.randint(1, 30)} blocks"],
        lambda: [f"{r.choice(['from', 'to', 'contract', 'wallet'])}: ", Val("0x" + pick(r, HEX, 40), "eth_address", False)],
        lambda: [f"sha256sum {r.choice(WORDS)}.zip\n", Val(pick(r, HEX, 64), "sha256", False), f"  {r.choice(WORDS)}.zip"],
        lambda: [f"--hash=sha256:", Val(pick(r, HEX, 64), "sha256", False)],
        lambda: [f"{r.choice(['Fixed in', 'Reverted', 'Cherry-picked', 'See'])} ", Val(pick(r, HEX, r.choice([7, 10, 40])), "git_sha", False), "."],
        lambda: [f"md5({r.choice(WORDS)}.iso) = ", Val(pick(r, HEX, 32), "md5", False)],
        lambda: [Val(pick(r, HEX, r.choice([32, 40, 64])), "sha256", False)],
    ])()


# ---------------------------------------------------------------------------------------------

FORMATS = ["env", "yaml", "json", "toml", "ini", "properties", "python", "js", "go", "java", "ruby", "php", "csharp",
           "shell", "dockerfile", "xml", "terraform", "log", "prose", "special", "html", "mixed"]
FORMAT_WEIGHTS = [8, 9, 7, 3, 3, 3, 9, 9, 4, 4, 3, 3, 3, 7, 3, 3, 3, 8, 7, 5, 3, 4]
CODE_LANGS = {"python", "js", "go", "java", "ruby", "php", "csharp"}


def filler_line(r: random.Random, w: Writer, fmt: str, indent: str) -> None:
    if fmt in CODE_LANGS:
        w.line(code_filler(r, fmt))
    elif fmt == "log":
        w.line(log_prefix(r), *log_filler(r))
    elif fmt == "prose":
        w.line(" ".join(sentence(r) for _ in range(r.randint(1, 3))) if r.random() < 0.8 else r.choice(["", "## " + comment_text(r), "- " + comment_text(r), "```"]))
    elif fmt == "html":
        w.line(r.choice([f"<div class=\"{ident(r, 'kebab')}\">{comment_text(r)}</div>", f"<link rel=\"stylesheet\" href=\"/static/{ident(r)}.css\">",
                         f"<p>{sentence(r)}</p>", "</div>", f"<a href=\"{url(r)}\">{comment_text(r)}</a>", "<meta charset=\"utf-8\">"]))
    elif fmt in ("shell", "dockerfile"):
        w.line(r.choice([f"# {comment_text(r)}", f"cd /srv/{ident(r)}", f"RUN apt-get install -y {r.choice(['curl', 'git', 'jq', 'libpq-dev'])}",
                         f"echo \"{comment_text(r)}\"", f"if [ -z \"${ident(r, 'upper')}\" ]; then", "fi", f"COPY . /app", f"npm run {r.choice(['build', 'test', 'lint'])}",
                         f"WORKDIR /app", f"set -euo pipefail", f"kubectl rollout status deploy/{ident(r, 'kebab')}"]))
    elif fmt == "xml":
        w.line(indent, r.choice([f"<{ident(r, 'camel')}>{plain_value(r)}</{ident(r, 'camel')}>", f"<!-- {comment_text(r)} -->", "<configuration>", "</appSettings>"]))
    else:
        if r.random() < 0.12:
            w.line(indent, r.choice(["# ", "// ", "; "]) if fmt not in ("json",) else "", comment_text(r))
            return
        assignment(r, w, fmt, split_words(plain_name(r, "snake")), [plain_value(r)], indent)


def body(r: random.Random, w: Writer, fmt: str, secret_rate: float, n_lines: int) -> None:
    indent = ""
    lang = fmt if fmt in CODE_LANGS else "python"
    if fmt == "yaml" and r.random() < 0.7:
        w.line(f"{r.choice(SERVICES)}:")
        indent = "  " * r.randint(1, 2)
    if fmt == "json":
        w.line("{")
        indent = "  "
    if fmt in ("toml", "ini"):
        w.line(f"[{r.choice(SERVICES)}]")
    for _ in range(n_lines):
        roll = r.random()
        if roll < secret_rate:
            if fmt in ("log", "prose", "shell") and r.random() < 0.7:
                w.line(*inline_secret(r, fmt))
            elif fmt in ("prose", "log") or (r.random() < 0.05 and fmt not in ("json",)):
                if r.random() < 0.5:
                    w.line(*private_key(r))
                else:
                    w.line(*inline_secret(r, r.choice(["prose", "log", "shell"])))
            elif fmt in CODE_LANGS and r.random() < 0.3:
                w.line(indent if fmt == "python" else "", *call_secret(r, lang))
            elif fmt in ("yaml", "json", "env", "toml", "ini", "xml") and r.random() < 0.08:
                assignment(r, w, fmt, split_words(r.choice(["url", "download_url", "webhook_url", "endpoint", "callback"])), url_with_secret(r), indent)
            else:
                value, words = secret_named(r)
                assignment(r, w, fmt if fmt not in ("html",) else "js", words, value, indent)
        elif roll < secret_rate + 0.3:
            sub = r.random()
            if sub < 0.2:
                decoy_block(r, w, fmt)
            elif sub < 0.28 and fmt in CODE_LANGS:
                w.line(*call_decoy(r, lang))
            elif sub < 0.38 and fmt in CODE_LANGS:
                name = secret_name(r, r.choice(["key", "secret", "token", "password"]), {"python": "upper", "js": "camel", "go": "camel"}.get(fmt, "snake"))
                op = {"go": " := ", "php": " = "}.get(fmt, " = ")
                w.line(name if fmt != "php" else "$" + name, op, Val(code_reference(r, lang), "code_reference", False), ";" if fmt in ("js", "java", "php", "csharp") else "")
            elif sub < 0.45 and fmt in ("log", "prose", "shell"):
                w.line(*inline_decoy(r, fmt))
            else:
                value, words = decoy_named(r)
                assignment(r, w, fmt if fmt not in ("log", "prose", "html") else "yaml", words, [value], indent)
        else:
            filler_line(r, w, fmt, indent)
    if fmt == "json":
        w.line("}")


def inline_decoy(r: random.Random, fmt: str) -> list[Piece]:
    """Running text that mentions secrets, or has random-looking values that are not secret."""
    return r.choice([
        lambda: [r.choice(["Set ", "Export ", "Put your key in "]), secret_name(r, "key", "upper"), r.choice([" before running.", " in your shell.", " (see the wiki)."])],
        lambda: ["The token is stored in ", Val(env_reference(r), "env_reference", False), "."],
        lambda: ["curl -H \"Authorization: Bearer ", Val(r.choice(["$TOKEN", "${GITHUB_TOKEN}", "$(cat token.txt)", "<token>", "YOUR_TOKEN"]), "placeholder", False), "\" https://api.example.com"],
        lambda: [f"mysql -u {r.choice(USERS)} -p ", f"-h {r.choice(HOSTS)}"],
        lambda: ["Release ", Val(pick(r, HEX, 40), "git_sha", False), " is live."],
        lambda: ["Request ", Val(rand_uuid(r), "uuid", False), " failed; please retry."],
        lambda: ["Password: ", Val(r.choice(["********", "<hidden>", "[REDACTED]", "(see 1Password)", "ask in #ops", "*****"]), "placeholder", False)],
        lambda: ["Download the checksum ", Val(pick(r, HEX, 64), "sha256", False), " and compare."],
        lambda: ["See ", Val(url(r), "url", False), " for details."],
        lambda: ["Rotate the API key every 90 days and never commit it."],
        lambda: bare_digest(r),
        lambda: bare_digest(r),
    ])()


def document(r: random.Random) -> Doc:
    w = Writer()
    fmt = r.choices(FORMATS, weights=FORMAT_WEIGHTS)[0]
    # A third of documents have no secret at all.
    secret_rate = 0.0 if r.random() < 0.33 else r.uniform(0.05, 0.3)
    n_lines = r.randint(3, 30)
    if fmt == "special":
        if r.random() < 0.5:
            filler_line(r, w, "ini", "")
        special_file(r, w)
    elif fmt == "mixed":
        # Docs with code blocks, or a config pasted into a chat.
        body(r, w, "prose", secret_rate / 2, r.randint(1, 6))
        w.line("```" + r.choice(["", "yaml", "bash", "python", "json"]))
        body(r, w, r.choice(["yaml", "shell", "python", "env", "json"]), secret_rate, r.randint(2, 12))
        w.line("```")
        body(r, w, "prose", secret_rate / 2, r.randint(1, 6))
    else:
        if fmt == "html":
            w.line("<!doctype html>")
        body(r, w, fmt, secret_rate, n_lines)
    doc = w.build()
    if r.random() < 0.1:
        doc = squash_newlines(doc, r)
    return doc


def squash_newlines(doc: Doc, r: random.Random) -> Doc:
    """Some text arrives on one line (minified JSON, a pasted log): swap newlines for spaces."""
    sep = r.choice([b" ", b"; ", b"\r\n"])
    text = bytearray()
    labels = []
    mapping = []
    for i, byte in enumerate(doc.text):
        if byte == 10:
            text += sep
            labels += [doc.labels[i]] * len(sep)
            mapping += [i] * len(sep)
        else:
            text.append(byte)
            labels.append(doc.labels[i])
            mapping.append(i)
    starts = {}
    for new, old in enumerate(mapping):
        starts.setdefault(old, new)
    starts[len(doc.text)] = len(text)

    def remap(spans):
        return [(starts[s], starts[e], k) for s, e, k in spans]

    return Doc(bytes(text), np.array(labels, np.uint8), remap(doc.secrets), remap(doc.decoys))


def generate(n: int, seed: int) -> list[Doc]:
    r = random.Random(seed)
    return [document(r) for _ in range(n)]
