# Value classifier training

Trains the model behind [`engine/models/value-classifier.onnx`](../engine/models/value-classifier.onnx), which a rule's value classifier setting runs on its matches. It says whether a matched value is a credential, a non-secret random string (a hash, digest, ID, or encoded data), or a placeholder. It judges the value and the name it's assigned to, not whether the file is a test or documentation. The engine's side of the contract is in [`engine/README.md`](../engine/README.md#value-classifier-setting).

## Retrain

Needs [uv](https://docs.astral.sh/uv/). From this folder:

```sh
uv venv .venv --python 3.12
VIRTUAL_ENV=.venv uv pip install -r requirements.txt
.venv/bin/python -m unittest test_encoding
.venv/bin/python train.py --creddata /path/to/CredData
```

`--creddata` (or `CREDDATA_DIR`) points at a local checkout of [Samsung/CredData](https://github.com/Samsung/CredData) with its `data/` built by its own `download_data.py`. Without it, training uses synthetic data alone. Training takes several minutes on a laptop CPU, and before training it scores the model it's about to replace on the same held-out data, so every retrain reports a before and after. It overwrites `engine/models/value-classifier.onnx` and prints the new file's SHA-256. Training is seeded, so the same code gives the same file on the same machine. Put the new hash in `VALUE_CLASSIFIER_SHA256` in `engine/src/defaults.rs`, then run `cargo test --features ml` in `engine/`.

A new hash is a new model to the engine: rule set versions that name the old hash report their classifier as unavailable until a new version uses the updated setting.

## Files

| File | What it does |
|---|---|
| [`encoding.py`](encoding.py) | Turns a value and its surrounding text into the token ids the engine sends, matching `engine/src/models.rs` |
| [`test_encoding.py`](test_encoding.py) | The same encoding cases as the engine's own tests, so the two can't drift apart |
| [`data.py`](data.py) | Generates labeled samples: a config or code snippet with one value in it |
| [`value_creddata.py`](value_creddata.py) | Reads labeled values from a local CredData checkout and splits them by repository |
| [`onnx_eval.py`](onnx_eval.py) | Runs a committed ONNX file in numpy, so the model being replaced can be scored too |
| [`train.py`](train.py) | Trains the network, reports results on each held-out set next to the previous model, and writes the ONNX file |

## The data

Training mixes two sources.

**Synthetic samples** (`data.py`, 40,000): one line of config or code that sets a name to a value, among a few ordinary lines. Like the engine, training shows the model only the value's own line. Real-shaped values are random at generation time, so no secret-looking string is committed.

| Class | Values | Names |
|---|---|---|
| Credential | Known formats (AWS, GitHub, npm, GitLab, Slack, Stripe live, Google, JWT), generic keys in hex, base64, or alphanumerics, made-up and human-style passwords, connection strings | Mostly secret-sounding (`password`, `api_key`, `token`), sometimes vague (`value`, `key`) |
| Non-secret | Commit and file hashes, image digests, `sha512-…` integrity strings, UUIDs, object and request IDs, base64 image data, public keys, URLs, paths, versions, numbers, colors, etags | Mostly names that say what they are (`commit`, `uuid`, `integrity`), sometimes vague or secret-sounding, where the value's shape has to decide |
| Placeholder | Documentation and placeholder values (`AKIAIOSFODNN7EXAMPLE`, `your_api_key_here`, `changeme`, `${API_KEY}`), format-shaped fakes (`ghp_xxxx…`), repeated or sequential characters, values with a placeholder word worked in (`…-CHANGE-ME`) | Mostly secret-sounding |

**CredData** (`value_creddata.py`): hand-labeled values from public repositories, at commit `fc9b64b`. Each single-line row that marks its value becomes a sample: `T` (a credential, including ones in test folders) is a credential, `F` (a false positive) is a non-secret, `X` (a test value, example, or placeholder) is a placeholder. Repos are split by a hash of their ID: 241 for training, 28 for validation, 63 for test, so no repo is in two splits. Each training repo contributes at most 400 values of each class, so no single repo dominates: 18,806 values in all. No CredData file is committed; each keeps its source project's license.

## The model

Byte embeddings, three dilated 1-D convolutions, a max over positions, and a three-way softmax: about 35,000 parameters. `train.py` writes the ONNX graph by hand from the trained weights (Gather, Transpose, Conv, Relu, ReduceMax, Gemm, Softmax at opset 13) instead of using PyTorch's exporter, so the file only uses operators tract runs. Training uses label smoothing so scores stay off 0 and 1.

Results, from the run that produced the committed model (classes are credential / non-secret / placeholder):

| Held-out data | Previous model (synthetic only) | This model |
|---|---|---|
| Synthetic, 4,000 values | accuracy 0.986 | accuracy 0.974 |
| CredData, 63 test repositories, 2,734 values | accuracy 0.491; 39% of credentials would get lower confidence | **accuracy 0.854; 9% of credentials would get lower confidence** |
| CredData, the 62 test repositories other than the one with the most credentials | accuracy 0.541; 35% | accuracy 0.840; 11% |
| CredData, 28 validation repositories | accuracy 0.423; 30% | accuracy 0.887; 6% |

On the CredData test repositories, credential precision and recall are 0.874 and 0.920, non-secret 0.815 and 0.829, placeholder 0.890 and 0.768. `engine/tests/value_classifier.rs` also checks it on hand-written cases. The limits are listed in the [engine README](../engine/README.md#the-value-classifier).

# Secret detector training

Trains the model behind [`engine/models/secret-detector.onnx`](../engine/models/secret-detector.onnx): a `model_detection` model that reads raw text and scores every byte for how likely it is part of a secret, so it can flag secrets no pattern rule describes. It is trained on synthetic documents mixed with real labeled code from [CredData](#creddata). The engine's side of the contract is in [`engine/README.md`](../engine/README.md#the-secret-detector).

## Retrain the detector

The shipped model needs a local CredData checkout (see [CredData](#creddata) for how to build one). With the venv from [Retrain](#retrain) above:

```sh
.venv/bin/python -m unittest test_encoding test_creddata
.venv/bin/python train_detector.py --creddata /path/to/CredData
```

Training takes about 25 minutes on a laptop CPU (4 threads), then evaluates on the held-out synthetic documents and CredData repositories. It overwrites `engine/models/secret-detector.onnx`, checks the written graph against PyTorch with ONNX's reference runtime, and prints the new file's SHA-256. Training is seeded and uses a fixed thread count, so the same code and the same CredData commit give the same file on the same machine. Put the new hash in `SECRET_DETECTOR_SHA256` in `engine/src/defaults.rs`, then run `cargo test --features ml` in `engine/`.

- Without `--creddata` it trains on synthetic documents only.
- `--evaluate MODEL.onnx` evaluates a written model without training (add `--creddata` to include the held-out repositories).
- `--docs`, `--epochs` and `--out` are for quick experiments; `--untrained --out PATH` writes the untrained network, for timing.

| Detector file | What it does |
|---|---|
| [`detector_data.py`](detector_data.py) | Generates documents with a label for every byte |
| [`creddata.py`](creddata.py) | Reads a CredData checkout into documents with a label for every byte, split by repository |
| [`test_creddata.py`](test_creddata.py) | Checks that CredData's labels land on the right bytes, with a tiny made-up checkout |
| [`train_detector.py`](train_detector.py) | Trains the network, reports held-out precision and recall the way the engine scores, and writes the ONNX file |
| [`encoding.py`](encoding.py) | `encode_window` matches the engine's detector input |

## Synthetic documents
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

## CredData

[CredData](https://github.com/Samsung/CredData) is Samsung's public benchmark for credential scanners: source files from public GitHub repositories in which the lines a set of scanners flagged were labeled by hand. The detector uses the checkout at commit `fc9b64b`, built with CredData's own `download_data.py`:

- **337 repositories, 11,565 files (997 MB).** 67,896 labeled lines: 15,753 `T` (a credential), 48,061 `F` (not one) and 4,082 `X` (a test value, example or placeholder).
- **Real credentials are already replaced:** CredData swaps each one for a random value with the same character set and length, keeping fixed prefixes. AWS keys keep their real prefix (`AKIA…`) with a random rest, never a documentation value such as `AKIAIOSFODNN7EXAMPLE`, so these rows don't teach the model that documentation values are secrets.
- **Nothing from it is committed here.** Each file keeps its source project's license (the license files sit in each repository's folder), so the repository only has the trained model and the code that reads a local checkout.

| License of the source repository | Repositories |
|---|---|
| MIT | 185 |
| Apache-2.0 | 94 |
| BSD-3-Clause | 17 |
| LGPL | 16 |
| ISC | 4 |
| BSD-2-Clause | 4 |
| CC0 | 3 |
| GPL | 1 |
| EPL | 1 |
| Other | 4 |
| No license file | 8 |

How [`creddata.py`](creddata.py) uses it:

- **Labels:**
  - A `T` row's value is labeled 1, using CredData's value position within the line.
  - A private key spanning several lines is labeled from its start to the end of its second line, the same rule as the synthetic keys, and the rest of it is left out of training.
  - Other `T` values that span several lines (two keys and the code between them), and `T` rows with no value position (1,003 of them), are left out of training.
  - `F` lines, `X` lines and all unlabeled text are labeled 0.
- **Split by repository:** one repository in five, chosen by a hash of its id, is held out for evaluation. That is 66 repositories (6,183 `T`, 13,360 `F`, 562 `X`); no file from them is trained on.
- **Training pieces:** from the other 271 repositories, about 770 bytes around every `T` and `X` line and two in five `F` lines, plus a random piece of one file in four: 29,479 pieces. They are mixed with the 32,000 synthetic documents.
- **Evaluation:** whole files, or for a file over 1 MB (the engine's limit for one scan), the text within 8 KB of its labels.

## The detector model

Byte embeddings, a 1×1 convolution, six residual dilated convolutions (kernel 3, dilations 1 to 32, so each byte sees about 64 bytes either side), a max over the window added back to every byte as a summary of the whole window, and one sigmoid score per byte: about 42,000 parameters. `L = 256`. `train_detector.py` writes the ONNX graph by hand (Gather, Transpose, Conv, Relu, Add, ReduceMax, Sigmoid, Flatten at opset 13). Training uses label smoothing so scores stay off 0 and 1.

## How good the detector is

Measured at the engine's default threshold of 50, the way the engine scores: windows every 128 bytes, each byte keeps its highest score, runs under 8 bytes dropped. A secret counts as found when a finding overlaps it; a finding counts as right when it overlaps a secret. Each source is reported on its own.

**Held-out CredData repositories**, comparing the shipped model with the previous one, trained on synthetic documents only:

| Held out | Synthetic only: precision / recall | With CredData: precision / recall |
|---|---|---|
| All 66 repositories (6,183 credentials) | 0.280 / 0.694 | **0.611 / 0.844** |
| The 65 other than `2ba83c6a` (1,018 credentials) | 0.074 / 0.563 | **0.405 / 0.750** |

- **One repository dominates.** `2ba83c6a` holds 84% of the held-out credentials (mostly keys and private keys, by the look of it test material in a cryptography project), so the second row is the better guide to ordinary code.
- **At threshold 70**, precision and recall are 0.770 / 0.645 on all 66 repositories and 0.563 / 0.698 on the other 65.
- **Recall by kind** on the other 65 repositories: tokens 186 of 190, private keys 30 of 31, UUID-shaped secrets 118 of 138, secrets 69 of 75, keys 50 of 59, passwords 202 of 360, URL credentials 5 of 19.
- **Most false positives are in unlabeled text** (965 of 1,205 on the other 65 repositories); 230 are on lines CredData labeled `F` and 10 on `X` lines. CredData only labels lines some scanner flagged, so some unlabeled findings may be real secrets nobody labeled, but most are random-looking strings in code.
- **Real values were obfuscated,** in training and evaluation alike. If the obfuscated values look different from real ones (CredData's replacement passwords are mostly lowercase letters and digits), these numbers can be better than on real code.

**Held-out synthetic documents** (2,000, a different seed from training): precision 0.958, recall 0.926 (0.988 / 0.884 at threshold 70). The synthetic-only model scored 0.959 / 0.958; adding real data cost some recall on the generator's own documents.

**Hand-written text**, in [`engine/tests/secret_detector.rs`](../engine/tests/secret_detector.rs), in three batches, each written before the model it was first checked against:

| Batch | How it was used | Secrets found | Wrong findings | Texts with no secret |
|---|---|---|---|---|
| 1 | Written before any training; the first model's misses (5 of 24) led to changes in the generator | 22 of 24 | 0 of 25 | 18, none flagged |
| 2 | Written before the second model was checked; its misses (4 of 13, plus 2 false positives) led to the last changes to the generator | 13 of 13 | 1 of 14 | 10, 1 flagged |
| 3 | Written before the third model was trained, and never used to change anything, including the move to CredData | **10 of 12** | **0 of 13** | **8, none flagged** |

On batch 3 the synthetic-only model found 11 of 12 with 2 of 14 findings wrong. The batches are small, and the person who wrote them also wrote the generator. What the shipped model still misses there: passwords with punctuation in a Markdown table and in a connection URL, an EC key indented inside a YAML block, a three-word password in an email; it flags a `0x` transaction hash.

## Detector limits

- **Precision on ordinary code is modest.** On held-out real repositories other than the dominant one, about 4 in 10 findings at threshold 50 are credentials (about 6 in 10 at 70). Treat findings as leads to review, not verdicts.
- **Passwords are the weakest kind**, at a little over half found on real code.
- **Its real data is one benchmark,** with obfuscated values, labels only on lines other scanners flagged, and one repository that dominates the held-out labels.
- **Each byte sees about 64 bytes either side** and a summary of its 256-byte window. A name further away than that doesn't help, and the middle of a long private key looks like a certificate, which is why only a key's first lines are labeled.
- **No test or example context.** A real-looking value in a unit test or a README is flagged like any other; placeholders are only recognized by their look.
- **Speed.** About 3.5 seconds for 1 MB in a release build on an Apple M1 Pro, 30 seconds in a debug build; see the [engine README](../engine/README.md#the-secret-detector).
- **Retraining changes the file's hash**, like the value classifier: rule set versions that name the old hash report the detector rule as unavailable until a new version names the new one.
