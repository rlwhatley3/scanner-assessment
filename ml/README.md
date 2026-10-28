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
