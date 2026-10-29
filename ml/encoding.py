"""The token ids the engine feeds a model, matching `engine/src/models.rs` exactly.

`0` pads, `1` and `2` mark where a value starts and ends, and each byte `b` of the text is `b + 3`.
A detector's window has no markers.
"""

PAD_ID = 0
VALUE_START_ID = 1
VALUE_END_ID = 2
BYTE_OFFSET = 3
VOCAB_SIZE = 256 + BYTE_OFFSET


def encode_value(text: bytes, start: int, end: int, length: int) -> list[int]:
    """A classifier's input for one value: the value between its markers, with as much of the
    text on either side as fits, split evenly when both sides have room. A value too long to fit
    is cut short and gets no surrounding text."""
    budget = max(length - 2, 0)
    value_end = min(end, start + budget)
    room = budget - (value_end - start)
    after = min(room - min(room // 2, start), len(text) - end)
    before = min(room - after, start)

    ids = [b + BYTE_OFFSET for b in text[start - before : start]]
    ids.append(VALUE_START_ID)
    ids += [b + BYTE_OFFSET for b in text[start:value_end]]
    ids.append(VALUE_END_ID)
    ids += [b + BYTE_OFFSET for b in text[end : end + after]]
    return ids + [PAD_ID] * (length - len(ids))


def encode_window(window: bytes, length: int) -> list[int]:
    """A detector's input for one window of text, padded to `length`."""
    ids = [b + BYTE_OFFSET for b in window]
    return ids + [PAD_ID] * (length - len(ids))
