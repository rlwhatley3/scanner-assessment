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
