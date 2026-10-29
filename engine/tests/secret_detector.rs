//! The trained secret detector in `models/`, run through the engine by its model detection rule.
//! The texts here are written by hand, not taken from the training generator, and many use
//! formats and surroundings the generator never produces. Secrets are marked `⟦like this⟧`; a
//! finding counts as right when it overlaps a marked secret.
//!
//! The cases come in three batches, each written before the model it was first checked against:
//!
//! 1. Written before any model was trained. The first model's misses here led to changes in the
//!    training data, so the model has been tuned against this batch.
//! 2. Written before the second model was checked. Its misses led to the last round of changes
//!    to the generator, so this batch is tuned against too.
//! 3. Written before the third model was trained, and kept out of every change since, including
//!    adding real data from CredData: the only batch here that shows how the detector does on
//!    text nobody tuned it for. `ml/README.md` has its results on held-out CredData repositories.
//!
//! Each batch's test asserts exactly what the detector gets wrong today, so a regression and an
//! improvement both show up as a failure to look at.
#![cfg(feature = "ml")]

use secrets_scanner_engine::{
    DetectionType, Models, Rule, RuleSet, SECRET_DETECTOR_ONNX, SECRET_DETECTOR_SHA256, ScanResult,
    Violation, scan_with_models, secret_detector_rule,
};
use std::ops::Range;
use std::time::Instant;

fn detect(text: &str) -> ScanResult {
    let mut models = Models::new();
    models
        .load(SECRET_DETECTOR_ONNX)
        .expect("the trained model should load");
    let rule_set = RuleSet {
        rules: vec![Rule {
            id: 1,
            definition: secret_detector_rule(),
        }],
    };
    scan_with_models(1, text, &rule_set, &models).expect("scan should run")
}

/// Token-shaped values, built from pieces so no token sits whole in the source for secret
/// scanners. `%name%` in a case's text is replaced with the value.
const VALUES: &[(&str, &[&str])] = &[
    ("github", &["ghp", "_NJSUL7cLRncFIj0qaDoM0nLQXVX6cL2anDAw"]),
    (
        "github_oauth",
        &["gho", "_Kp4Rz8Tq1Wm6Yv3Xn9Bs2Lc7Hd5Fj0Ga8Ue7"],
    ),
    ("stripe", &["sk_", "live_", "RQnnDfN8517n0cRfmFdP7Iwj"]),
    (
        "aws_secret",
        &["tsYwF/vELX1NVuDQ", "mQ+1oi/NrgdMxTrMboHZ1QWJ"],
    ),
    (
        "mailchimp",
        &["7b40b4ce3911326c", "6b8c8e84c7637a30", "-us6"],
    ),
    ("datadog_api", &["c394628e6003384f", "e96725aee6050bfe"]),
    (
        "datadog_app",
        &["5e5ea1f041acbf0dea8f", "2f3926342ccc9c231b46"],
    ),
    ("cohere", &["PsuvDVNgwDZBIQrUJNGG", "Od3JLkwuC2KXvvmXytiS"]),
    (
        "planetscale",
        &[
            "pscale",
            "_pw_",
            "uRf1LHICt6bStxZMZaNPEbTo0h8FKLJ5o7zVbJLpXJc",
        ],
    ),
    (
        "dockerhub",
        &["dckr", "_pat_", "MCJ3nPCu7p0-wke2WMu_qqBJRLD"],
    ),
    (
        "grafana",
        &["glsa", "_XEO5SlPUiyw7a1Njet2l1EDx0v0YAvB6", "_5301456f"],
    ),
    (
        "linear",
        &["lin", "_api_", "TvcbjmMPl3FpnFwIgeDRvE0YGAAiVyrBgMDPrgHB"],
    ),
    ("shopify", &["shpat", "_05c7f59d7dba47da10d9c9ff1b21f05d"]),
    (
        "telegram",
        &["1750670707", ":MwfEpf8acVxckLPx8vedU3w7oslOor8Rb_k"],
    ),
    (
        "sas_signature",
        &["tPD01CtcgkScUxYl3eyX9whaT", "%2B%2F8v%2F90Rd0z%2BrLLEho%3D"],
    ),
    (
        "hex_secret",
        &[
            "1b8de038bbbce003514d54cbda46e15b",
            "fa6f562858ef63cd6c876ccb3acb3619",
        ],
    ),
    (
        "base64_secret",
        &["1E6t+pJrzNHZO6EP7ke", "nYYqvcO5Nsz9OaxVy36hcQMw="],
    ),
    (
        "github_server",
        &["ghs", "_hZ5PFyhPQF0zBzCvLROOJwRIMGdNZd40xs5L"],
    ),
    (
        "slack_webhook",
        &["T61JS5ZAR", "/B5W74KIUFSR/", "tBk5JLCKkfDXevgy7QMVmNiP"],
    ),
    (
        "fcm",
        &[
            "AAAAnL73Wfb",
            ":APA91bzSsv2_UIh18GiQhJdqilw-NyK_hPA6FXBeIWG8XL2BscbFu9ZYi49SbIz0_516fuIKYRSPuwiPSVqx25VKp_h9rP58TVA7bs_sDEiN-OjJnNzlWac6511eN8woxM-WwMeZ4sws",
        ],
    ),
    ("vercel", &["vcp", "_rn6B48MOdtMDdJCZ68sYhiYB"]),
    ("replicate", &["r8", "_iRmh3G1OV9s6pfzsq85V4MfHBcKMNyLJFBhL2"]),
    (
        "azure_key",
        &[
            "rzokVsG1TjXwmdWx0I1wx0bRe0YnTrgcCn7VvQlIWZrZkAHI6vkEE5Yy",
            "r+UFfRbA6UV1+8IdTTFv3h/G7nVxeA==",
        ],
    ),
    (
        "openssh_key",
        &[
            "-----BEGIN OPENSSH PRIVATE KEY-----
  b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW⟧
",
            "  of0I0sMSmo/UHVE7blHfl8ZXyQT3ar1keRbuoB/gWYqr9lqhSwHEhyfgFW/Vnlmjt/r2UB8ZB0
",
            "  Xbx040yeY4/PMjhZW4jDEFmmx2E0BnEzPAaW33olPo6EbcxJV8t5t9n3/KLKunPpE9ecm6rplXruh2H9VDby7W
",
            "  -----END OPENSSH PRIVATE KEY-----",
        ],
    ),
    (
        "ec_key",
        &[
            "-----BEGIN EC PRIVATE KEY-----\n    MHcCAQEEIjAxTR/9tFOKGl8iOUGKPehT/pk66W54dWD2uZGoDG4bvd/aZmA4b⟧\n",
            "    /FsSh44KYvMCI++cU6YXPR0KACVTgn3cuVW17Owt+hnJJwYlwrN1h5NBAl/gcY/S\n",
            "    5+pZviWczdQaxkX87xqcwnc3GYri3Ak3XmY/Iz113ISaUw==\n",
            "    -----END EC PRIVATE KEY-----",
        ],
    ),
];

fn fill(text: &str) -> String {
    VALUES
        .iter()
        .fold(text.to_string(), |text, (name, pieces)| {
            text.replace(&format!("%{name}%"), &pieces.concat())
        })
}

/// The text with its `⟦⟧` markers removed, and the byte ranges they marked.
fn parse(marked: &str) -> (String, Vec<Range<usize>>) {
    let marked = fill(marked);
    let mut text = String::new();
    let mut spans = Vec::new();
    let mut start = 0;
    for c in marked.chars() {
        match c {
            '⟦' => start = text.len(),
            '⟧' => spans.push(start..text.len()),
            c => text.push(c),
        }
    }
    (text, spans)
}

/// What the detector got wrong in one text: marked secrets no finding overlaps, and findings
/// that overlap no marked secret.
#[derive(Debug, Default)]
struct Outcome {
    secrets: usize,
    findings: usize,
    missed: Vec<String>,
    wrong: Vec<String>,
}

fn check(marked: &str) -> Outcome {
    let (text, secrets) = parse(marked);
    let result = detect(&text);
    let found: Vec<(Range<usize>, u8)> = result
        .findings
        .iter()
        .map(|finding| match &finding.violation {
            Violation::Match(details) => {
                assert_eq!(details.detection_type, DetectionType::ModelDetection);
                (
                    details.location.start_byte..details.location.end_byte,
                    details.confidence,
                )
            }
            Violation::RuleError(error) => panic!("unexpected rule error: {error:?}"),
        })
        .collect();
    let overlaps = |a: &Range<usize>, b: &Range<usize>| a.start < b.end && b.start < a.end;
    Outcome {
        secrets: secrets.len(),
        findings: found.len(),
        missed: secrets
            .iter()
            .filter(|secret| !found.iter().any(|(span, _)| overlaps(span, secret)))
            .map(|secret| text[secret.clone()].to_string())
            .collect(),
        wrong: found
            .iter()
            .filter(|(span, _)| !secrets.iter().any(|secret| overlaps(span, secret)))
            .map(|(span, score)| format!("{:?} (score {score})", &text[span.clone()]))
            .collect(),
    }
}

/// Batch 1: texts with secrets in them, in formats or places the first model's training data
/// never had: vendors with no prefix rule, a password as a positional argument, a `.pgpass` line,
/// an indented key in a YAML block, a URL-encoded signature.
const BATCH_1_WITH_SECRETS: &[(&str, &str)] = &[
    (
        "env file with a vendor token",
        "# copied from 1Password, do not commit\nAPP_ENV=production\nGITHUB_TOKEN=⟦%github%⟧\nSENTRY_ENVIRONMENT=prod\n",
    ),
    (
        "django settings",
        "DEBUG = False\nALLOWED_HOSTS = [\"shop.example.com\"]\nSECRET_KEY = '⟦#n=*f!x^l$ru*nwm!18y+j6fe85wokct!3ku)8@cn2c$678uat⟧'\nDATABASES = {\"default\": {\"ENGINE\": \"django.db.backends.postgresql\", \"NAME\": \"shop\"}}\n",
    ),
    (
        "docker compose password",
        "services:\n  db:\n    image: postgres:16\n    environment:\n      POSTGRES_USER: shop\n      POSTGRES_PASSWORD: ⟦Wq9#tLm2vX!e⟧\n    ports:\n      - \"5432:5432\"\n",
    ),
    (
        "stripe key passed straight to the client",
        "const stripe = require('stripe')('⟦%stripe%⟧');\n\napp.post('/checkout', async (req, res) => {\n  const session = await stripe.checkout.sessions.create(req.body);\n",
    ),
    (
        "chat message with a cloud secret",
        "hey @maria — the new secret for the backup bucket is ⟦%aws_secret%⟧, swap it in before friday pls 🙏\n",
    ),
    (
        "mailchimp key in curl",
        "curl -X GET 'https://us6.api.mailchimp.com/3.0/lists' --user \"anystring:⟦%mailchimp%⟧\"\n",
    ),
    (
        "terraform provider block",
        "provider \"datadog\" {\n  api_key = \"⟦%datadog_api%⟧\"\n  app_key = \"⟦%datadog_app%⟧\"\n  api_url = \"https://api.datadoghq.eu/\"\n}\n",
    ),
    (
        "unnamed key passed to an SDK",
        "import cohere\n\nco = cohere.Client(\"⟦%cohere%⟧\")\nresponse = co.chat(message=\"hello\")\nprint(response.text)\n",
    ),
    (
        "password as a positional argument",
        "Connection conn = DriverManager.getConnection(\"jdbc:mysql://localhost:3306/shop\", \"shop_admin\", \"⟦pR7!zQ2#kL9m⟧\");\n",
    ),
    (
        "pgpass line",
        "db.example.com:5432:*:appuser:⟦N0tS0S3cret!2024⟧\n",
    ),
    (
        "indented private key in a YAML block",
        "apiVersion: v1\nkind: Secret\nmetadata:\n  name: edge-tls\nstringData:\n  tls.key: |\n    ⟦%ec_key%\n",
    ),
    (
        "token in a CI log",
        "2026-10-27T09:14:02.5531Z ##[group]Run curl -sSf -H \"Authorization: token ⟦%github_oauth%⟧\" https://api.github.com/repos/acme/web/releases\n2026-10-27T09:14:03.0012Z ##[endgroup]\n",
    ),
    (
        "tokens from vendors no rule describes",
        "PLANETSCALE_PASSWORD=⟦%planetscale%⟧\nDOCKERHUB_TOKEN=⟦%dockerhub%⟧\nGRAFANA_SA_TOKEN=⟦%grafana%⟧\nLINEAR_API_KEY=⟦%linear%⟧\n",
    ),
    (
        "chat bot token in code",
        "import telebot\n\nbot = telebot.TeleBot(\"⟦%telegram%⟧\")\n\n@bot.message_handler(commands=[\"start\"])\n",
    ),
    (
        "signature in a shared-access URL",
        "Download: https://acmebackups.blob.core.windows.net/db/dump.sql?sv=2022-11-02&ss=b&srt=o&sp=r&se=2026-12-01T00:00:00Z&sig=⟦%sas_signature%⟧\n",
    ),
    (
        "access token header in an HTTP dump",
        "POST /admin/api/2024-07/graphql.json HTTP/1.1\nHost: acme-store.myshopify.com\nX-Shopify-Access-Token: ⟦%shopify%⟧\nContent-Type: application/json\n",
    ),
    (
        "hex signing secret in JSON",
        "{\n  \"name\": \"orders-webhook\",\n  \"signingSecret\": \"⟦%hex_secret%⟧\",\n  \"events\": [\"order.created\"]\n}\n",
    ),
    (
        "base64 secret in rails credentials",
        "production:\n  secret_key_base: ⟦%base64_secret%⟧\n  aws:\n    region: eu-central-1\n",
    ),
    (
        "temporary password in an email",
        "Hi Sam,\n\nYour account on the build server is ready. Username: sam.k, temporary password: ⟦Lantern-Orbit-42⟧. You'll be asked to change it on first login.\n\nThanks,\nIT\n",
    ),
    (
        "password in a runbook command",
        "3. Connect to the replica:\n\n       mysql -h replica-2.internal -u repl -p'⟦v8$Kd!2mQz⟧' -e \"SHOW SLAVE STATUS\\G\"\n\n4. Check Seconds_Behind_Master.\n",
    ),
];

/// Batch 1: texts with nothing secret in them, full of things that look random or mention
/// secrets.
const BATCH_1_WITHOUT_SECRETS: &[(&str, &str)] = &[
    (
        "package-lock entry",
        "    \"node_modules/lodash\": {\n      \"version\": \"4.17.21\",\n      \"resolved\": \"https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz\",\n      \"integrity\": \"sha512-1DZ6UOdIartW57KUr0HBmJEftbLtTU2GqHROO4vIoKhJX2OTdMqFrvVqnkjRTSgPocuSvcj19foz9BMtVlLQ+A==\",\n      \"dev\": true\n    },\n",
    ),
    (
        "git log",
        "commit 423a7ceecf7de229a342dd3e1dc050298055b9cc\nMerge: ff28727 1b8de03\nAuthor: Priya N <priya@acme.dev>\nDate:   Tue Oct 27 16:02:11 2026 +0100\n\n    Merge pull request #2231 from acme/fix-retry-backoff\n\ncommit ff287271e7d50b404c8029cc5a67ea8d71da535a\n",
    ),
    (
        "inline favicon and a pinned script",
        "<link rel=\"icon\" href=\"data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQgjdhherHuvK86U+r4tWxbtfRMMpzeObIc9k+MmicT1gAXabdotCbVYq0AGxzRUjHdki9pE54eTY8G5skHuanzhxiAgAw9pswDr0+swm5nNNK+S7pR4ck1ePR\">\n<script src=\"https://cdn.example.net/htmx.min.js\" integrity=\"sha384-gjdhherHuvK86U+r4tWxbtfRMMpzeObIc9k+MmicT1gAXabdotCbVYq0AGxzRUjH\" crossorigin=\"anonymous\"></script>\n",
    ),
    (
        "deployment with an image digest and secret references",
        "      containers:\n        - name: api\n          image: ghcr.io/acme/api@sha256:2fcd15b5ea36ccea043720c9567a743ccd84952ac25c01e05df2e4dbd429e2c8\n          env:\n            - name: DB_PASSWORD\n              valueFrom:\n                secretKeyRef:\n                  name: db-credentials\n                  key: password\n",
    ),
    (
        "readme with placeholders",
        "## Setup\n\nCreate a `.env` file:\n\n```\nOPENAI_API_KEY=\"your-key-here\"\nGITHUB_TOKEN=<your token>\n```\n\nor configure the AWS CLI with the documented sample values:\n\n    aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n    aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n",
    ),
    (
        "application log",
        "2026-10-28 10:41:07.311 INFO  [http-nio-8080-exec-4] c.a.orders.OrderController - order 8f14e45f-ceea-467a-9575-9e5e4f6f3c11 placed by customer 48213 (trace 4bf92f3577b34da6a3ce929d0e0e4736)\n2026-10-28 10:41:07.402 WARN  [http-nio-8080-exec-4] c.a.pay.Gateway - retrying charge ch_3PqR7sLmN2xYz after 503\n",
    ),
    (
        "authorized_keys",
        "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIf+gwiX67xu3Uj7wmla5YQUTCbB+uHhrK+jjRDQ6EgLA= deploy@build-03\n",
    ),
    (
        "secrets read from the environment",
        "DB_PASSWORD = os.environ[\"DB_PASSWORD\"]\nSTRIPE_KEY = os.getenv(\"STRIPE_SECRET_KEY\", \"\")\nclient = Client(api_key=settings.API_KEY, timeout=30)\n",
    ),
    (
        "minified bundle",
        "!function(e,t){\"object\"==typeof exports?module.exports=t():e.qz=t()}(this,function(){var e=[],t=0;function n(r){return e[r]||(e[r]=t++)}return{id:n,reset:function(){e=[],t=0}}});\n",
    ),
    (
        "cargo lockfile",
        "[[package]]\nname = \"serde\"\nversion = \"1.0.229\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"2fcd15b5ea36ccea043720c9567a743ccd84952ac25c01e05df2e4dbd429e2c8\"\n",
    ),
    (
        "password policy",
        "Passwords must be at least 12 characters and are rotated every 90 days. Never share your password or API key over chat; use the vault instead.\n",
    ),
    (
        "go.sum",
        "golang.org/x/net v0.31.0 h1:rTh0dZNhwZlDIDNWBY5GL18G7GBXrNzrkyAYXYOYTKY=\ngolang.org/x/net v0.31.0/go.mod h1:f+gwiX67xu3Uj7wmla5YQUTCbB+uHhrK+jjRDQ6EgLA=\n",
    ),
    (
        "links with tracking parameters",
        "Watch the recap: https://www.youtube.com/watch?v=dQw4w9WgXcQ&list=PLx0sYbCqOb8TBPRdmBHs5Iftvv9TPboYG&index=3\nSlides: https://docs.example.com/d/1BxiMVs0XRA5nFMdKvBdBZjgmUUqptlbs74OgvE2upms/edit?usp=sharing\n",
    ),
    (
        "public certificate",
        "-----BEGIN CERTIFICATE-----\nMIIDKYWwIR2RLTUDuk2C/Iw48GziwofWlYF5uS8zKC2MEnPNYQqZ7+1BrPgbASoA\nSXXTZj3QR5TD43HXFWNDg261V9KIW6GGIw4utUCOK5/Mk/QLH4YCyuqmlrFp3P61\nZ8BXevCftqGIzh/WZKw7h1miUy9gdn6F/aozxgb6Tbu7cL8MFS05i/AsrRssGg4q\n-----END CERTIFICATE-----\n",
    ),
    (
        "checksums file",
        "2fcd15b5ea36ccea043720c9567a743ccd84952ac25c01e05df2e4dbd429e2c8  scanner-v1.4.0-linux-amd64.tar.gz\n1b8de038bbbce003514d54cbda46e15bfa6f562858ef63cd6c876ccb3acb3619  scanner-v1.4.0-darwin-arm64.tar.gz\n",
    ),
    (
        "asset manifest",
        "{\n  \"files\": {\n    \"main.js\": \"/static/js/main.4f8c2a1e.js\",\n    \"main.css\": \"/static/css/main.9b3d7e05.css\"\n  },\n  \"entrypoints\": [\"static/js/runtime.c71b5a0d.js\"]\n}\n",
    ),
    (
        "settings named after secrets",
        "auth:\n  token_ttl_seconds: 3600\n  password_min_length: 12\n  api_key_header: X-Api-Key\n  secret_store: aws-secrets-manager\n",
    ),
    (
        "test with obviously fake values",
        "def test_redacts_tokens():\n    token = \"not-a-real-token\"\n    assert redact(f\"Bearer {token}\") == \"Bearer [REDACTED]\"\n",
    ),
];

/// Batch 2.
const BATCH_2_WITH_SECRETS: &[(&str, &str)] = &[
    (
        "wordpress config",
        "define( 'DB_NAME', 'wp_shop' );\ndefine( 'DB_USER', 'wp_shop' );\ndefine( 'DB_PASSWORD', '⟦xK9#mQ2$vL7pR4⟧' );\ndefine( 'AUTH_KEY',         '⟦D55V_IR&f5.>(X{Kpo/jQna+_RK[In~.AN#q1]eS<s_^j**,J/@m(5vb4GB,-XlW⟧' );\n",
    ),
    (
        "api key header in a Go client",
        "\treq, _ := http.NewRequest(\"GET\", base+\"/v3/forecast\", nil)\n\treq.Header.Set(\"X-API-Key\", \"⟦lZ8EVeIz4J7utmglhJ1LcaEL4qPr0akS⟧\")\n\tresp, err := c.http.Do(req)\n",
    ),
    (
        "ansible vars",
        "---\nansible_user: deploy\nansible_become: true\nansible_become_password: ⟦Sp4rrow!Tide⟧\nnginx_worker_processes: auto\n",
    ),
    (
        "powershell secure string",
        "$user = \"CORP\\svc-backup\"\n$securePassword = ConvertTo-SecureString \"⟦Qz8!wN3@fT6x⟧\" -AsPlainText -Force\n$cred = New-Object System.Management.Automation.PSCredential($user, $securePassword)\n",
    ),
    (
        "git config remote with a token",
        "[remote \"origin\"]\n\turl = https://x-access-token:⟦%github_server%⟧@github.com/acme/infra.git\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n",
    ),
    (
        "chat webhook in a Jenkinsfile",
        "post {\n  failure {\n    slackSend(webhookUrl: 'https://hooks.slack.com/services/⟦%slack_webhook%⟧', message: \"Build ${env.BUILD_NUMBER} failed\")\n  }\n}\n",
    ),
    (
        "push server key in gradle properties",
        "org.gradle.jvmargs=-Xmx2048m\nandroid.useAndroidX=true\nFCM_SERVER_KEY=⟦%fcm%⟧\n",
    ),
    (
        "auth token pasted into a ticket",
        "Customer pasted their Twilio auth token (⟦400df255ce3a0b835a2d4247b962311d⟧) into the support form. We should purge the ticket and ask them to rotate it.\n",
    ),
    (
        "kotlin constant",
        "object ApiConfig {\n    const val BASE_URL = \"https://api.acme.io/\"\n    private const val CLIENT_SECRET = \"⟦VZrcriyIc4LFgTDNWRs5VJ2FV6atucF0U5nbSbyU⟧\"\n}\n",
    ),
    (
        "sql dump row",
        "INSERT INTO api_clients (id, name, client_secret, created_at) VALUES (3, 'mobile', '⟦QpBumi2Ye9xTbM6NsQUSbDnojvhmEZNQVrWyU4TZqlF1ee8w⟧', '2026-03-02 10:00:00');\n",
    ),
    (
        "systemd unit",
        "[Service]\nUser=cache\nEnvironment=\"REDIS_PASSWORD=⟦c7Hn2!pQw9Zr⟧\"\nExecStart=/usr/local/bin/cache-warmer --interval 60\n",
    ),
    (
        "gem server credentials",
        "BUNDLE_GEMS__CONTRIBSYS__COM: \"⟦975644c9:0a95c790⟧\"\nBUNDLE_JOBS: \"4\"\n",
    ),
];

const BATCH_2_WITHOUT_SECRETS: &[(&str, &str)] = &[
    (
        "yarn lockfile",
        "react@^18.3.1:\n  version \"18.3.1\"\n  resolved \"https://registry.yarnpkg.com/react/-/react-18.3.1.tgz#01b15d5df0c9de1ad23c7b2f5bddb2ec21487ceb\"\n  integrity sha512-JHwXLPqYkIL0EzwTQh64l4xPbfAgt5jjhgJX4brexD+qNVfqLi8/tPXLim4vO+OU808K09gmwxCpXwIYsNAB9g==\n",
    ),
    (
        "terraform state",
        "        \"attributes\": {\n          \"arn\": \"arn:aws:iam::123456789012:role/ci-deployer\",\n          \"unique_id\": \"AROAM52ZMW3U4OHNP8V2F\",\n          \"instance_id\": \"i-0779b93f7d8490cab\",\n          \"name\": \"ci-deployer\"\n        }\n",
    ),
    (
        "dockerfile checksum check",
        "ENV NODE_VERSION=20.18.0\nRUN curl -fsSLO https://nodejs.org/dist/v20.18.0/node-v20.18.0-linux-x64.tar.xz \\\n  && echo \"ecdcf9314f36c34cb8d287f34acc568aa62ba12e5daeea9213c38f247c45576e  node-v20.18.0-linux-x64.tar.xz\" | sha256sum -c -\n",
    ),
    (
        "svg in css",
        ".icon-home {\n  background-image: url(\"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCI+PHBhdGggZD0iTTEyIDJMMiA3bDEwIDUgMTAtNS0xMC01eiIvPjwvc3ZnPg==\");\n}\n",
    ),
    (
        "notebook output image",
        "     \"output_type\": \"display_data\",\n     \"data\": {\n      \"image/png\": \"iVBORw0KGgoAAAANSUhEUgAAubWiN35/IfNlkr8iIv6myFRoD/3oytre/YT1LECP1lesPpWOxwWRT2lsPI+l+GK1PcduhxlXjGUJiDkEzJFYNN5hAaU/g/SczaXkYLnApyWaBDD9ZL47bm7186H+hajvIhk3WmEhpHgCwbfAnwi58MFpjfsCmW5vVLY4Mfb4kIrm6YwDm117xLaczENrpis8YME6H3yl\",\n",
    ),
    (
        "content security policy",
        "Content-Security-Policy: default-src 'self'; script-src 'nonce-ejyy7RCr/cyN+iyUR+sKwQ==' 'sha256-uWO9MEt0CFHq2oWVVUy1gQ2bPkBPizz+/kzf7HEOlpw='; object-src 'none'\n",
    ),
    (
        "openapi security scheme",
        "components:\n  securitySchemes:\n    ApiKeyAuth:\n      type: apiKey\n      in: header\n      name: X-API-Key\nsecurity:\n  - ApiKeyAuth: []\n",
    ),
    (
        "transaction hash in a log",
        "12:04:55 payout worker: tx 0x2f3dad01d194e6f3391fa920a5db423c24b9b7c0fc6420d4b4ea6f6658246abd confirmed after 12 blocks\n",
    ),
    (
        "pinned requirements",
        "requests==2.32.3 \\\n    --hash=sha256:85d68272726b12d922e42b6c2cf1ec189a3ac3cec24773db77c58e845a72d520\n",
    ),
    (
        "newsletter footer",
        "Unsubscribe: https://acme.us6.list-manage.com/unsubscribe?u=66457288688eed230a426a881&id=d782969d56\n",
    ),
];

/// Batch 3, the held-out batch.
const BATCH_3_WITH_SECRETS: &[(&str, &str)] = &[
    (
        "elixir config",
        "config :shop, ShopWeb.Endpoint,\n  url: [host: \"shop.example.com\", port: 443],\n  secret_key_base: \"⟦zgUTro0CHYH7crUrgnxETe4q+vJN3TeYn0pjDg7SBzR2QKnTefIELizojFCxwlwb⟧\"\n",
    ),
    (
        "rust client with a bearer token",
        "let resp = reqwest::Client::new()\n    .get(\"https://api.weatherly.dev/v1/now\")\n    .bearer_auth(\"⟦JB6L55vVvjafrJFROl2aSjDWlFkuw3mvJjkZRuwd⟧\")\n    .send()\n    .await?;\n",
    ),
    (
        "swift constant",
        "enum Keys {\n    static let maps = \"⟦d5ebc22cf7e04710186517a85d1b2338⟧\" // TODO: move to the keychain\n}\n",
    ),
    (
        "helm values",
        "postgresql:\n  enabled: true\n  auth:\n    username: shop\n    postgresPassword: \"⟦Ember#Quartz88⟧\"\n    database: shop\n",
    ),
    (
        "makefile",
        "deploy:\n\tTOKEN=⟦%vercel%⟧ ./scripts/release.sh --prod\n",
    ),
    (
        "markdown table of logins",
        "| env | user | password |\n|---|---|---|\n| staging | admin | ⟦Gw4!rT9#pLx2⟧ |\n",
    ),
    (
        "crontab backup job",
        "0 3 * * * pg_dump \"postgresql://backup:⟦R1v3r!Delta⟧@db.internal/app\" > /backups/app-$(date +\\%F).sql\n",
    ),
    (
        "basic auth in a raw request",
        "GET /reports/weekly.csv HTTP/1.1\nHost: reports.internal\nAuthorization: Basic ⟦c3ZjLXJlcG9ydHM6SlBUanZlSjBlWkZ3SVk=⟧\nAccept: text/csv\n",
    ),
    (
        "function app settings",
        "{\n  \"IsEncrypted\": false,\n  \"Values\": {\n    \"AzureWebJobsStorage\": \"DefaultEndpointsProtocol=https;AccountName=fnstore;AccountKey=⟦%azure_key%⟧;EndpointSuffix=core.windows.net\",\n    \"FUNCTIONS_WORKER_RUNTIME\": \"python\"\n  }\n}\n",
    ),
    (
        "notebook cell",
        "import os\nos.environ[\"REPLICATE_API_TOKEN\"] = \"⟦%replicate%⟧\"\nimport replicate\n",
    ),
    (
        "gradle publishing credentials",
        "repositories {\n    maven {\n        url = uri(\"https://nexus.acme.dev/repository/releases\")\n        credentials {\n            username = \"ci-bot\"\n            password = \"⟦niOmy6lp2ZKpXsVGMmZ0JHq_BgXeS4Ak⟧\"\n        }\n    }\n}\n",
    ),
    (
        "deploy key in ansible vars",
        "deploy_user: release\ndeploy_key: |\n  ⟦%openssh_key%\n",
    ),
];

const BATCH_3_WITHOUT_SECRETS: &[(&str, &str)] = &[
    (
        "projected service account token",
        "      volumes:\n        - name: token\n          projected:\n            sources:\n              - serviceAccountToken:\n                  audience: vault\n                  expirationSeconds: 3600\n                  path: token\n",
    ),
    (
        "build manifest",
        "{\"buildId\":\"1k4V77tYzLNFNTct3nny2\",\"assetPrefix\":\"\",\"runtimeConfig\":{},\"isFallback\":false,\"gsp\":true}\n",
    ),
    (
        "postman variables",
        "\"header\": [\n  { \"key\": \"Authorization\", \"value\": \"Bearer {{access_token}}\" },\n  { \"key\": \"X-Api-Key\", \"value\": \"{{api_key}}\" }\n]\n",
    ),
    (
        "hex dump",
        "00000000: 7f45 4c46 0201 0100 0000 0000 0000 0000  .ELF............\n00000010: 0300 3e00 0100 0000 a01b 0000 0000 0000  ..>.............\n",
    ),
    (
        "gpg key listing",
        "pub   rsa4096 2023-01-12 [SC] [expires: 2027-01-12]\n      1244D907FF0E6FE2920A55E6AFA27980AF861E6F\nuid           [ultimate] Ana Ruiz <ana@acme.dev>\nsub   rsa4096 2023-01-12 [E]\n",
    ),
    (
        "compose file with required variables",
        "  db:\n    image: postgres:16.4\n    environment:\n      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?set it in .env}\n    healthcheck:\n      test: [\"CMD\", \"pg_isready\"]\n",
    ),
    (
        "known hash in a test",
        "def test_sha1():\n    assert hashlib.sha1(b\"abc\").hexdigest() == \"a9993e364706816aba3e25717850c26c9cd0d89d\"\n",
    ),
    (
        "changelog with commit links",
        "### Fixed\n- Race in the scheduler when two jobs share a lock ([6c1b4c3](https://github.com/acme/app/commit/6c1b4c33dcd46d58351987e17418c9f2d8e9ae58))\n",
    ),
];

/// Runs a batch and prints how it went. Returns the names of the cases with a missed secret
/// and the names of the cases with a wrong finding, once per miss or wrong finding.
fn run(batch: &str, with: &[(&str, &str)], without: &[(&str, &str)]) -> (Vec<String>, Vec<String>) {
    let (mut secrets, mut findings, mut missed, mut wrong) = (0, 0, Vec::new(), Vec::new());
    let mut details = Vec::new();
    for (name, marked) in with.iter().chain(without) {
        let outcome = check(marked);
        secrets += outcome.secrets;
        findings += outcome.findings;
        for secret in &outcome.missed {
            missed.push(name.to_string());
            details.push(format!("{name}: missed {secret:?}"));
        }
        for finding in &outcome.wrong {
            wrong.push(name.to_string());
            details.push(format!("{name}: flagged {finding}"));
        }
    }
    println!(
        "{batch}: {} of {secrets} secrets found; {} of {findings} findings wrong ({} texts with \
         secrets, {} without)\n{details:#?}",
        secrets - missed.len(),
        wrong.len(),
        with.len(),
        without.len()
    );
    (missed, wrong)
}

#[test]
fn the_model_loads_under_the_hash_its_rule_names() {
    let mut models = Models::new();
    assert_eq!(
        models.load(SECRET_DETECTOR_ONNX).unwrap(),
        SECRET_DETECTOR_SHA256
    );
}

#[test]
fn batch_1() {
    let (missed, wrong) = run("batch 1", BATCH_1_WITH_SECRETS, BATCH_1_WITHOUT_SECRETS);
    // A hex key with a `-us6` suffix after `anystring:`, and a three-word password in an email.
    assert_eq!(
        missed,
        ["mailchimp key in curl", "temporary password in an email"]
    );
    assert!(wrong.is_empty(), "{wrong:?}");
}

#[test]
fn batch_2() {
    let (missed, wrong) = run("batch 2", BATCH_2_WITH_SECRETS, BATCH_2_WITHOUT_SECRETS);
    // A 17-character `hex:hex` credential under a name that doesn't sound secret.
    assert_eq!(missed, ["gem server credentials"]);
    assert!(wrong.is_empty(), "{wrong:?}");
}

#[test]
fn batch_3_held_out() {
    let (missed, wrong) = run("batch 3", BATCH_3_WITH_SECRETS, BATCH_3_WITHOUT_SECRETS);
    // A password with punctuation in a connection URL in a crontab.
    assert_eq!(missed, ["crontab backup job"]);
    assert!(wrong.is_empty(), "{wrong:?}");
}

#[test]
fn a_finding_says_the_detector_flagged_it() {
    let (text, _) = parse(BATCH_1_WITH_SECRETS[0].1);
    let result = detect(&text);
    let Violation::Match(details) = &result.findings[0].violation else {
        panic!("expected a match");
    };
    assert!(details.confidence >= 50);
    assert!(
        details
            .why_flagged
            .starts_with("Flagged by the Secret detector model"),
        "{}",
        details.why_flagged
    );
}

/// How long the detector takes on 1 MB of mixed text. Run it with
/// `cargo test --release --features ml --test secret_detector -- --ignored --nocapture`.
#[test]
#[ignore = "a timing, not a check"]
fn time_a_one_megabyte_scan() {
    let block = "# service settings\nDATABASE_HOST=db.internal\nLOG_LEVEL=info\n\
                 def handler(event, context):\n    return {\"status\": 200, \"body\": event}\n\
                 2026-10-28T12:00:00Z INFO request_id=6f1c2a4e-8b3d-4c5e-9f7a-1b2c3d4e5f60 done\n";
    let text = block.repeat(1_000_000 / block.len());
    let started = Instant::now();
    let result = detect(&text);
    println!(
        "{} bytes in {:.2?}, {} findings",
        text.len(),
        started.elapsed(),
        result.findings.len()
    );
}
