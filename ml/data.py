"""Synthetic training data for the value classifier.

The classifier says what a matched value is, from the value itself and the name it is assigned
to: a credential, a non-secret random string (a hash, ID, digest, or encoded data), or a
placeholder. It does not judge whether the surrounding file is a test or documentation; that is
a separate question for a different model. Each sample is a short piece of config or code with
one value in it, the value's byte range, and its class.

Real-shaped values are generated at random, so no secret-looking string is written here.
"""

import base64
import random
import string
from dataclasses import dataclass

CREDENTIAL = 0
NON_SECRET = 1
PLACEHOLDER = 2
CLASSES = ["credential", "non_secret", "placeholder"]

UPPER_DIGITS = string.ascii_uppercase + string.digits
ALNUM = string.ascii_letters + string.digits
BASE64 = ALNUM + "+/"
URLSAFE = ALNUM + "-_"
HEX = "0123456789abcdef"
SYMBOLS = "!@#$%^&*-_=+?"
WORDS = ["summer", "winter", "dragon", "monkey", "sunshine", "qwerty", "admin", "welcome",
         "tiger", "falcon", "orange", "coffee", "rocket", "shadow", "mustang", "silver"]


@dataclass
class Sample:
    text: bytes
    start: int
    end: int
    label: int


def pick(r: random.Random, alphabet: str, n: int) -> str:
    return "".join(r.choice(alphabet) for _ in range(n))


def b64(r: random.Random, n_bytes: int) -> str:
    return base64.b64encode(r.randbytes(n_bytes)).decode()


def human_password(r: random.Random) -> str:
    word = r.choice(WORDS)
    word = word.capitalize() if r.random() < 0.6 else word
    return word + str(r.randint(1, 9999)) + r.choice(["", "!", "#", "$", "@", "?"])


# Credentials: known formats, generic keys, and passwords.
CREDENTIALS = [
    lambda r: "AKIA" + pick(r, UPPER_DIGITS, 16),
    lambda r: pick(r, BASE64, 40),
    lambda r: r.choice(["ghp_", "gho_", "ghs_", "npm_"]) + pick(r, ALNUM, 36),
    lambda r: "glpat-" + pick(r, URLSAFE, 20),
    lambda r: "xoxb-" + pick(r, string.digits, 12) + "-" + pick(r, string.digits, 13) + "-" + pick(r, ALNUM, 24),
    lambda r: r.choice(["sk_live_", "rk_live_"]) + pick(r, ALNUM, 24),
    lambda r: "AIza" + pick(r, URLSAFE, 35),
    lambda r: "eyJ" + pick(r, URLSAFE, 30) + "." + pick(r, URLSAFE, 60) + "." + pick(r, URLSAFE, 43),
    lambda r: pick(r, HEX, r.choice([32, 40, 64])),
    lambda r: pick(r, ALNUM, r.randint(20, 40)),
    lambda r: b64(r, r.randint(18, 36)),
    lambda r: pick(r, ALNUM + SYMBOLS, r.randint(10, 24)),
    human_password,
    lambda r: f"postgres://app:{pick(r, ALNUM, 16)}@db.internal:5432/main",
]

# Non-secret strings that look random: hashes, digests, IDs, and encoded data.
NON_SECRETS = [
    lambda r: pick(r, HEX, 40),  # commit
    lambda r: pick(r, HEX, 7),  # short commit
    lambda r: pick(r, HEX, 64),  # file digest
    lambda r: "sha256:" + pick(r, HEX, 64),  # image digest
    lambda r: r.choice(["sha512-", "sha384-", "sha1-"]) + b64(r, r.choice([64, 48, 20])),  # integrity
    lambda r: "-".join(pick(r, HEX, n) for n in (8, 4, 4, 4, 12)),  # UUID
    lambda r: pick(r, HEX, 24),  # object id
    lambda r: "data:image/png;base64," + b64(r, r.randint(30, 60)),
    lambda r: r.choice(["req_", "evt_", "cus_", "txn_", "ord_"]) + pick(r, ALNUM, 24),
    lambda r: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA" + pick(r, BASE64, 43),  # public key
    lambda r: "https://cdn.example.com/assets/" + pick(r, HEX, 16) + ".js",
    lambda r: "/var/lib/app/" + pick(r, string.ascii_lowercase, 8) + "/" + pick(r, HEX, 12),
    lambda r: f"{r.randint(0, 9)}.{r.randint(0, 40)}.{r.randint(0, 200)}+build.{pick(r, HEX, 8)}",
    lambda r: pick(r, string.digits, r.randint(10, 19)),  # timestamp or numeric id
    lambda r: "#" + pick(r, HEX, 6),
    lambda r: "W/\"" + pick(r, HEX, 32) + "\"",  # etag
]

# Placeholder, documentation, and made-up values.
PLACEHOLDER_WORDS = ["CHANGE-ME", "CHANGEME", "change_me", "EXAMPLE", "example", "REPLACE",
                     "replace-me", "dummy", "DUMMY", "fake", "FAKE", "sample", "placeholder",
                     "notreal", "TODO", "your", "YOUR", "xxx"]
PLACEHOLDERS = [
    lambda r: r.choice([
        "AKIAIOSFODNN7EXAMPLE", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "your_api_key_here",
        "YOUR_API_KEY", "YOUR_SECRET_KEY_HERE", "your-token-goes-here", "insert_your_key_here",
        "REPLACE_WITH_YOUR_TOKEN", "REPLACE_ME", "changeme", "change_me_please", "<your-api-key>",
        "<TOKEN>", "dummy-secret-value", "dummy_password", "fake-api-key", "test-secret-123",
        "testpassword", "example-token-1234", "secret123", "password123", "password", "s3cr3t",
        "not-a-real-key", "TODO_set_me", "${API_KEY}", "{{ secret }}", "%SECRET%", "<redacted>",
        "********", "REDACTED",
    ]),
    lambda r: r.choice("xX*0") * r.randint(8, 40),
    lambda r: r.choice(["AKIA", "ghp_", "npm_", "sk_live_", "glpat-"]) + r.choice("xX0aA") * r.randint(16, 36),
    lambda r: r.choice(["AKIA", "ghp_", "sk_test_"]) + "EXAMPLE" + pick(r, UPPER_DIGITS, 9),
    lambda r: r.choice(["0123456789", "abcdef", "1234", "abc123", "qwerty"]) * r.randint(2, 6),
    lambda r: r.choice(["", pick(r, ALNUM + SYMBOLS, r.randint(3, 8)) + r.choice("-_")])
    + r.choice(PLACEHOLDER_WORDS)
    + r.choice(["", r.choice("-_") + pick(r, ALNUM + SYMBOLS, r.randint(3, 8))]),
]

SECRET_KEYS = ["api_key", "apiKey", "API_KEY", "secret", "client_secret", "SECRET_KEY", "token",
               "access_token", "auth_token", "GITHUB_TOKEN", "password", "db_password",
               "PASSWORD", "aws_secret_access_key", "private_key", "slack_token", "passwd",
               "DATABASE_URL", "credentials", "session_secret"]
NEUTRAL_KEYS = ["value", "key", "data", "config_value", "x", "VALUE", "param", "setting"]
NON_SECRET_KEYS = ["commit", "sha", "revision", "digest", "checksum", "integrity", "etag", "id",
                   "uuid", "request_id", "trace_id", "object_id", "hash", "fingerprint",
                   "public_key", "image", "icon", "url", "path", "version", "build_id",
                   "created_at", "color", "customer_id", "event_id"]

FILLER = [
    "region: us-east-1", "debug = false", "port: 8080", "timeout_ms: 3000", "log_level=info",
    "name = \"billing-service\"", "replicas: 3", "host: db.internal", "retries = 5",
    "ENVIRONMENT=production", "enabled: true", "import os", "import requests",
    "const client = createClient(config);", "server:", "database:", "[default]", "}", "{",
    "max_connections = 100", "user: app", "BASE_URL=https://api.internal", "version: \"3.9\"",
    "# Settings", "def test_parse():", "## Example", "it('loads config', () => {",
]


def line(key: str, r: random.Random) -> tuple[str, str]:
    """A line that sets `key`, split around the value."""
    style = r.randrange(8)
    if style == 0:
        return f"{key.upper()}=", ""
    if style == 1:
        return f"export {key.upper()}=\"", "\""
    if style == 2:
        return f"  {key}: ", ""
    if style == 3:
        return f"  \"{key}\": \"", "\","
    if style == 4:
        return f"{key} = \"", "\""
    if style == 5:
        return f"const {key} = '", "';"
    if style == 6:
        return f"client = Client({key}=\"", "\")"
    return f"    {key} = \"", "\""


def sample(r: random.Random) -> Sample:
    kind = r.random()
    if kind < 0.4:
        value, label = r.choice(CREDENTIALS)(r), CREDENTIAL
        key = r.choice(SECRET_KEYS if r.random() < 0.8 else NEUTRAL_KEYS)
    elif kind < 0.75:
        value, label = r.choice(NON_SECRETS)(r), NON_SECRET
        # Mostly under a name that says what it is, sometimes under a vague or secret-sounding
        # one, where the value's own shape has to decide.
        roll = r.random()
        key = r.choice(NON_SECRET_KEYS if roll < 0.7 else NEUTRAL_KEYS if roll < 0.85 else SECRET_KEYS)
    else:
        value, label = r.choice(PLACEHOLDERS)(r), PLACEHOLDER
        key = r.choice(SECRET_KEYS if r.random() < 0.8 else NEUTRAL_KEYS)

    head, tail = line(key, r)
    before = r.sample(FILLER, r.randint(0, 3))
    after = r.sample(FILLER, r.randint(0, 3))
    prefix = "\n".join(before + [head])
    text = prefix + value + tail + ("\n" + "\n".join(after) if after else "")
    start = len(prefix.encode())
    return Sample(text.encode(), start, start + len(value.encode()), label)


def generate(count: int, seed: int) -> list[Sample]:
    r = random.Random(seed)
    return [sample(r) for _ in range(count)]
