"""The token ids the engine feeds a model, matching `engine/src/models.rs` exactly.

`0` pads, `1` and `2` mark where a value starts and ends, and each byte `b` of the text is `b + 3`.
"""

PAD_ID = 0
VALUE_START_ID = 1
VALUE_END_ID = 2
BYTE_OFFSET = 3
VOCAB_SIZE = 256 + BYTE_OFFSET


def line_bounds(text: bytes, start: int, end: int) -> tuple[int, int]:
    """The line or lines holding `start:end`: from just after the line break before `start` to
    just before the line break at or after `end`. `\\n`, `\\r\\n`, and a lone `\\r` all break
    lines."""
    line_start = max(text.rfind(b"\n", 0, start), text.rfind(b"\r", 0, start)) + 1
    breaks = [i for i in (text.find(b"\n", end), text.find(b"\r", end)) if i != -1]
    return line_start, min(breaks, default=len(text))


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
