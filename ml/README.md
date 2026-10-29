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

The code as it stands trains a model with SHA-256 `b3a1537c…5752`, not the shipped `6980e353…c6cc`: see [the split](#the-split-and-the-shipped-model) for why the shipped file was kept. Restore the shipped file with `git checkout ../engine/models/value-classifier.onnx` after a retrain you don't mean to ship.

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

**Synthetic samples** (`data.py`, 20,000): one line of config or code that sets a name to a value, among a few ordinary lines. Like the engine, training shows the model only the value's own line. Real-shaped values are random at generation time, so no secret-looking string is committed.

| Class | Values | Names |
|---|---|---|
| Credential | Known formats (AWS, GitHub, npm, GitLab, Slack, Stripe live, Google, JWT), generic keys in hex, base64, or alphanumerics, made-up and human-style passwords, connection strings | Mostly secret-sounding (`password`, `api_key`, `token`), sometimes vague (`value`, `key`) |
| Non-secret | Commit and file hashes, image digests, `sha512-…` integrity strings, UUIDs, object and request IDs, base64 image data, public keys, URLs, paths, versions, numbers, colors, etags | Mostly names that say what they are (`commit`, `uuid`, `integrity`), sometimes vague or secret-sounding, where the value's shape has to decide |
| Placeholder | Documentation and placeholder values (`AKIAIOSFODNN7EXAMPLE`, `your_api_key_here`, `changeme`, `${API_KEY}`), format-shaped fakes (`ghp_xxxx…`), repeated or sequential characters, values with a placeholder word worked in (`…-CHANGE-ME`) | Mostly secret-sounding |

**CredData** (`value_creddata.py`): hand-labeled values from public repositories, at commit `fc9b64b`. Each single-line row that marks its value becomes a sample: `T` (a credential, including ones in test folders) is a credential, `F` (a false positive) is a non-secret, `X` (a test value, example, or placeholder) is a placeholder. Repos are split with the secret detector's rule (`split_of`, the same as the detector's `creddata.split_of`): a SHA-256 of the repo ID puts one in five in test and one in eight of the rest in validation. That is 234 training, 37 validation and 66 test repos, so no repo is in two splits, and both models hold out the same test repos. Each training repo contributes at most 400 values of each class, so no single repo dominates: 16,738 values from the 232 training repos that have usable rows. Settings, such as the number of synthetic samples, are chosen on the validation repos, never on test. No CredData file is committed; each keeps its source project's license.

## The model

Byte embeddings, three dilated 1-D convolutions, a max over positions, and a three-way softmax: about 35,000 parameters. `train.py` writes the ONNX graph by hand from the trained weights (Gather, Transpose, Conv, Relu, ReduceMax, Gemm, Softmax at opset 13) instead of using PyTorch's exporter, so the file only uses operators tract runs. Training uses label smoothing so scores stay off 0 and 1.

## The split and the shipped model

The shipped model (`6980e353…c6cc`) was trained before the classifier used the detector's split. Its own hash split put 51 of the detector's 66 test repos in its training data, among them `2ba83c6a`, which holds 82% of the test credentials (4,365 of 5,347 values). The code now uses the detector's split. It was retrained, and the candidate (`b3a1537c…5752`) was kept out of the engine because it does worse on the test repos. Both models were scored on the same data (classes are credential / non-secret / placeholder; "lowered" is the share of credentials scoring under 50, which would get lower confidence):

| Held-out data | Values | Shipped model | Retrained on the detector's split |
|---|---|---|---|
| CredData, the 66 test repos | 9,963 | accuracy 0.975; 2.2% lowered (trained on 51 of these repos) | accuracy 0.473; 65.6% lowered |
| CredData, the 65 test repos other than `2ba83c6a` | 3,686 | accuracy 0.959; 2.2% (trained on 50 of these repos) | accuracy 0.880; 10.0% |
| CredData, the 15 test repos neither model trained on | 1,002 | accuracy 0.885; 2.8% | accuracy 0.845; 5.0% |
| CredData, the 37 validation repos | 2,846 | accuracy 0.960; 2.5% (trained on 28 of these repos) | accuracy 0.868; 11.6% |
| Synthetic | 4,000 | accuracy 0.974; 2.3% | accuracy 0.972; 3.8% |
| Hand-written cases in `engine/tests/value_classifier.rs` | 10 | all 10 rated as expected | all 10 rated as expected |

Two test repos and one validation repo have no single-line row that marks its value, so they contribute no values. Most of the retrained model's loss on the 66 test repos is `2ba83c6a`, whose rows are mostly keys in `.txt` files: 3,395 labeled `T` beside 4,191 labeled `F`. The shipped model learned that repo, and the retrained one has never seen it. The only comparison that's fair to both is the 15 repos neither trained on, and the shipped model is ahead there too, though 1,002 values is a small sample.

So until a retrain beats it on those repos, the engine keeps the shipped model. Its numbers on the detector's test repos are not held-out numbers. An evaluation that needs a classifier that has never seen those repos should train one with `train.py`, as above.

`engine/tests/value_classifier.rs` checks the shipped model on hand-written cases. The limits are listed in the [engine README](../engine/README.md#the-value-classifier).
