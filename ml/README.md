# Value classifier training

Trains the model behind [`engine/models/value-classifier.onnx`](../engine/models/value-classifier.onnx), which a rule's value classifier setting runs on its matches. It says whether a matched value is a credential, a non-secret random string (a hash, digest, ID, or encoded data), or a placeholder. It judges the value and the name it's assigned to, not whether the file is a test or documentation. The engine's side of the contract is in [`engine/README.md`](../engine/README.md#value-classifier-setting).

## Retrain

Needs [uv](https://docs.astral.sh/uv/). From this folder:

```sh
uv venv .venv --python 3.12
VIRTUAL_ENV=.venv uv pip install -r requirements.txt
.venv/bin/python -m unittest test_encoding
.venv/bin/python train.py
```

Training takes about three minutes on a laptop CPU. It overwrites `engine/models/value-classifier.onnx` and prints the new file's SHA-256. Training is seeded, so the same code gives the same file on the same machine. Put the new hash in `VALUE_CLASSIFIER_SHA256` in `engine/src/defaults.rs`, then run `cargo test --features ml` in `engine/`.

A new hash is a new model to the engine: rule set versions that name the old hash report their classifier as unavailable until a new version uses the updated setting.

## Files

| File | What it does |
|---|---|
| [`encoding.py`](encoding.py) | Turns a value and its surrounding text into the token ids the engine sends, matching `engine/src/models.rs` |
| [`test_encoding.py`](test_encoding.py) | The same encoding cases as the engine's own tests, so the two can't drift apart |
| [`data.py`](data.py) | Generates labeled samples: a config or code snippet with one value in it |
| [`train.py`](train.py) | Trains the network, reports held-out accuracy, and writes the ONNX file |

## The data

Every sample is synthetic: one line of config or code that sets a name to a value, among a few ordinary lines. Like the engine, training shows the model only the value's own line. Real-shaped values are random at generation time, so no secret-looking string is committed.

| Class | Values | Names |
|---|---|---|
| Credential | Known formats (AWS, GitHub, npm, GitLab, Slack, Stripe live, Google, JWT), generic keys in hex, base64, or alphanumerics, made-up and human-style passwords, connection strings | Mostly secret-sounding (`password`, `api_key`, `token`), sometimes vague (`value`, `key`) |
| Non-secret | Commit and file hashes, image digests, `sha512-…` integrity strings, UUIDs, object and request IDs, base64 image data, public keys, URLs, paths, versions, numbers, colors, etags | Mostly names that say what they are (`commit`, `uuid`, `integrity`), sometimes vague or secret-sounding, where the value's shape has to decide |
| Placeholder | Documentation and placeholder values (`AKIAIOSFODNN7EXAMPLE`, `your_api_key_here`, `changeme`, `${API_KEY}`), format-shaped fakes (`ghp_xxxx…`), repeated or sequential characters, values with a placeholder word worked in (`…-CHANGE-ME`) | Mostly secret-sounding |

## The model

Byte embeddings, three dilated 1-D convolutions, a max over positions, and a three-way softmax: about 35,000 parameters. `train.py` writes the ONNX graph by hand from the trained weights (Gather, Transpose, Conv, Relu, ReduceMax, Gemm, Softmax at opset 13) instead of using PyTorch's exporter, so the file only uses operators tract runs. Training uses label smoothing so scores stay off 0 and 1.

Held-out accuracy on generated data is about 99%; most misses are hex strings under ambiguous names, which are hard on purpose. That number only shows the model learned the generator. `engine/tests/value_classifier.rs` checks it on hand-written cases instead. The limits are listed in the [engine README](../engine/README.md#the-value-classifier).
