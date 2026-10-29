# Value classifier training

Trains the model behind [`engine/models/value-classifier.onnx`](../engine/models/value-classifier.onnx): a `model_assessment` model that rates a finding's value as likely real or likely an example. The engine's side of the contract is in [`engine/README.md`](../engine/README.md#model-rules).

## Retrain

Needs [uv](https://docs.astral.sh/uv/). From this folder:

```sh
uv venv .venv --python 3.12
VIRTUAL_ENV=.venv uv pip install -r requirements.txt
.venv/bin/python -m unittest test_encoding
.venv/bin/python train.py
```

Training takes about three minutes on a laptop CPU. It overwrites `engine/models/value-classifier.onnx` and prints the new file's SHA-256. Training is seeded, so the same code gives the same file on the same machine. Put the new hash in `VALUE_CLASSIFIER_SHA256` in `engine/src/defaults.rs`, then run `cargo test --features ml` in `engine/`.

A new hash is a new model to the engine: rule set versions that name the old hash report the classifier rule as unavailable until a new version includes the updated rule.

## Files

| File | What it does |
|---|---|
| [`encoding.py`](encoding.py) | Turns a value and its surrounding text into the token ids the engine sends, matching `engine/src/models.rs` |
| [`test_encoding.py`](test_encoding.py) | The same encoding cases as the engine's own tests, so the two can't drift apart |
| [`data.py`](data.py) | Generates labeled samples: a config or code snippet with one value in it |
| [`train.py`](train.py) | Trains the network, reports held-out accuracy, and writes the ONNX file |

## The data

Every sample is synthetic. Real-shaped values are random at generation time, so no secret-looking string is committed.

| Label | What it looks like |
|---|---|
| Real (1) | A random value in a known format (AWS, GitHub, npm, GitLab, Slack, Stripe live) or a generic high-entropy string or password, set in an ordinary config or code line. Some have an unrelated example or test line nearby, so only a cue at the value itself counts |
| Example (0) | A documentation or placeholder value (`AKIAIOSFODNN7EXAMPLE`, `your_api_key_here`, `changeme`), a format-shaped fake (`ghp_xxxx…`, `sk_test_…`), a value with a placeholder word worked in (`…-CHANGE-ME`), or any value in a test or example context |

## The model

Byte embeddings, three dilated 1-D convolutions, a max over positions, and one sigmoid output: about 35,000 parameters. `train.py` writes the ONNX graph by hand from the trained weights (Gather, Transpose, Conv, Relu, ReduceMax, Gemm, Sigmoid at opset 13) instead of using PyTorch's exporter, so the file only uses operators tract runs. Training uses label smoothing so scores stay off 0 and 1.

Held-out accuracy on generated data is effectively 100%, which only shows that the model learned the generator. `engine/tests/value_classifier.rs` checks it on hand-written cases instead. The limits are listed in the [engine README](../engine/README.md#the-value-classifier).

# Secret detector training

Trains the model behind [`engine/models/secret-detector.onnx`](../engine/models/secret-detector.onnx): a `model_detection` model that reads raw text and scores every byte for how likely it is part of a secret, so it can flag secrets no pattern rule describes. The engine's side of the contract is in [`engine/README.md`](../engine/README.md#the-secret-detector).

## Retrain the detector

With the venv from [Retrain](#retrain) above:

```sh
.venv/bin/python -m unittest test_encoding
.venv/bin/python train_detector.py
```

Training takes about 35 minutes on a laptop CPU (4 threads). It overwrites `engine/models/secret-detector.onnx`, checks the written graph against PyTorch with ONNX's reference runtime, and prints the new file's SHA-256. Training is seeded and uses a fixed thread count, so the same code gives the same file on the same machine. Put the new hash in `SECRET_DETECTOR_SHA256` in `engine/src/defaults.rs`, then run `cargo test --features ml` in `engine/`. `--docs`, `--epochs` and `--out` make quick experiments easy; `--untrained --out PATH` writes the untrained network, for timing.

| Detector file | What it does |
|---|---|
| [`detector_data.py`](detector_data.py) | Generates documents with a label for every byte |
| [`train_detector.py`](train_detector.py) | Trains the network, reports held-out precision and recall the way the engine scores, and writes the ONNX file |
| [`encoding.py`](encoding.py) | `encode_window` matches the engine's detector input |

## The detector's data

Every document is synthetic, and real-shaped values are random at generation time, so no secret-looking string is committed. A document is one of about twenty kinds of file (env, YAML, JSON, TOML, INI, properties, Python, JavaScript, Go, Java, Ruby, PHP, C#, shell, Dockerfile, XML, Terraform, logs, prose and chat, HTML, credential files such as `.netrc`, `.npmrc`, `.pgpass`, service-account JSON and Kubernetes secrets, and Markdown with code blocks). A third of documents have no secret at all; about a tenth have their newlines squashed, the way minified JSON or a pasted log arrives.

| Labeled 1 | Labeled 0 |
|---|---|
| Known formats (AWS, GitHub, GitLab, Slack, Stripe, Google, SendGrid, LLM providers, npm, PyPI, Hugging Face, Twilio, Mailgun, DigitalOcean, Shopify, Azure storage) | Hashes and digests (git SHAs, SHA-256, MD5, `sha256:` image digests, `0x` transaction hashes, checksum files, lockfile entries, `go.sum`) |
| Made-up vendor tokens: a random short prefix and random characters, so the model learns the shape rather than a list | UUIDs, trace and request IDs, IDs with prefixes (`cus_…`, `i-0…`), ARNs, build hashes, pagination cursors |
| Generic hex, alphanumeric and base64 keys, salts, and IDs joined to secrets (`123456:abc…`, `…-us6`) | Base64 image and font data, SRI `integrity` strings, public keys, certificates, SSH keys, fingerprints |
| Passwords: words with digits, leetspeak, passphrases, random strings with every symbol | URLs with tracking parameters, minified code |
| JWTs, private keys (from `-----BEGIN` to the end of the first line of key data), base64-encoded credentials | Placeholders (`your_api_key_here`, `AKIAIOSFODNN7EXAMPLE`, `xxxx…`, `********`), references (`${DB_PASSWORD}`, `os.environ[…]`, `{{ secrets.X }}`, vault paths) |
| The password in a connection string or URL, a token after `Bearer` or in `--user`, a signature in a query string, a webhook URL's secret path | Settings named after secrets that hold no secret (`password_min_length: 12`, `token_type: bearer`) |

Secrets sit under names in every case style, under bland names when their format gives them away, passed straight to a function (`Client("…")`, `connect(host, user, "…")`, `ConvertTo-SecureString "…"`), and in running text, commands and log lines.

Each training step takes one 256-byte window from each document, placed the way the engine places windows: at the start, on a 128-byte boundary, or anywhere, sometimes running off the end into padding.

## The detector model

Byte embeddings, a 1×1 convolution, six residual dilated convolutions (kernel 3, dilations 1 to 32, so each byte sees about 64 bytes either side), a max over the window added back to every byte as a summary of the whole window, and one sigmoid score per byte: about 42,000 parameters. `L = 256`. `train_detector.py` writes the ONNX graph by hand (Gather, Transpose, Conv, Relu, Add, ReduceMax, Sigmoid, Flatten at opset 13). Training uses label smoothing so scores stay off 0 and 1.

## How good the detector is

Measured at the engine's default threshold of 50, the way the engine scores: windows every 128 bytes, each byte keeps its highest score, runs under 8 bytes dropped. A secret counts as found when a finding overlaps it; a finding counts as right when it overlaps a secret.

**On 2,000 held-out generated documents** (a different seed from training): precision 0.959, recall 0.958 (0.986 / 0.936 at threshold 70; 0.904 / 0.971 at 30). Recall is 1.0 or close to it for known formats, JWTs, private keys, webhook URLs and generic keys; passwords are the weakest at 0.89 (737 of 829), and passwords in connection strings 0.90. The false positives are mostly base64 image data, SSH public keys, digests, SRI strings and prefixed IDs. These numbers mostly show that the model learned the generator.

**On hand-written text**, in [`engine/tests/secret_detector.rs`](../engine/tests/secret_detector.rs), in three batches, each written before the model it was first checked against:

| Batch | How it was used | Secrets found | Wrong findings | Texts with no secret |
|---|---|---|---|---|
| 1 | Written before any training; the first model's misses (5 of 24) led to changes in the data | 23 of 24 | 0 of 25 | 18, none flagged |
| 2 | Written before the second model was checked; its misses (4 of 13, plus 2 false positives) led to the last round of changes | 13 of 13 | 1 of 14 | 10, none flagged |
| 3 | Written before the final model was trained, and never used to change anything | **11 of 12** | **2 of 14** | **8, none flagged** |

Only batch 3 is a fair test. On it the final model finds 11 of 12 secrets and is wrong in 2 of 14 findings (precision 0.86, recall 0.92); the second model, which had not seen batch 3 either, scored 11 of 12 and 0 of 13. On batch 2, while it was still held out, the second model found 9 of 13 with 2 false positives in 10 clean texts. Treat the true rate on real text as somewhere around those held-out numbers, not the generated ones: these batches are small (25 secrets and 18 clean texts held out in all), and the person who wrote them also wrote the generator.

What it still gets wrong, from these batches:

- A bare 32-character hex key under a bland name (`static let maps = "…"`) is missed: without a secret-sounding name, hex looks like a hash.
- A hex key with a suffix after a fixed user (`--user "anystring:…-us6"`), found by the second model, is missed by the final one.
- Table borders and settings next to a secret (`|---|---|`, `=-Xmx2048m`) are sometimes flagged as their own findings.

## Detector limits

- **It learned a generator.** Every training document is synthetic. It has not been trained or checked on real repositories, so expect misses and false positives in formats and surroundings unlike anything above.
- **Each byte sees about 64 bytes either side** and a summary of its 256-byte window. A name further away than that doesn't help, and the middle of a long private key looks like a certificate, which is why only a key's first lines are labeled.
- **No test or example context.** A real-looking value in a unit test or a README is flagged like any other; placeholders are only recognized by their look.
- **Speed.** About 3.5 seconds for 1 MB in a release build on an Apple M1 Pro, 30 seconds in a debug build; see the [engine README](../engine/README.md#the-secret-detector).
- **Retraining changes the file's hash**, like the value classifier: rule set versions that name the old hash report the detector rule as unavailable until a new version names the new one.
