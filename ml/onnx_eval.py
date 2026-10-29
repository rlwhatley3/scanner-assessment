"""Runs a value classifier ONNX file in numpy, so a committed model can be scored against a new one
without an ONNX runtime. It handles exactly the graph `train.py` writes: Gather, Transpose, Conv,
Relu, ReduceMax, Gemm, Softmax."""

from pathlib import Path

import numpy as np
import onnx
from onnx import numpy_helper


def load(path: Path):
    model = onnx.load(str(path))
    weights = {t.name: numpy_helper.to_array(t) for t in model.graph.initializer}
    convs = []
    for node in model.graph.node:
        if node.op_type == "Conv":
            attrs = {a.name: onnx.helper.get_attribute_value(a) for a in node.attribute}
            convs.append((weights[node.input[1]], weights[node.input[2]], attrs["dilations"][0], attrs["pads"][0]))
    return weights["embed.weight"], convs, weights["out.weight"], weights["out.bias"]


def predict(model, ids: np.ndarray, batch: int = 512) -> np.ndarray:
    """Class probabilities for each row of token ids."""
    embed, convs, out_w, out_b = model
    results = []
    for start in range(0, len(ids), batch):
        x = embed[ids[start : start + batch]].transpose(0, 2, 1)  # [N, channels, L]
        for weight, bias, dilation, pad in convs:
            padded = np.pad(x, ((0, 0), (0, 0), (pad, pad)))
            length = x.shape[2]
            y = np.zeros((x.shape[0], weight.shape[0], length), dtype=np.float32)
            for k in range(weight.shape[2]):
                window = padded[:, :, k * dilation : k * dilation + length]
                y += np.einsum("ncl,oc->nol", window, weight[:, :, k])
            x = np.maximum(y + bias[None, :, None], 0)
        logits = x.max(axis=2) @ out_w.T + out_b
        logits -= logits.max(axis=1, keepdims=True)
        exp = np.exp(logits)
        results.append(exp / exp.sum(axis=1, keepdims=True))
    return np.concatenate(results)
