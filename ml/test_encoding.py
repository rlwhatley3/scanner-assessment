"""The same cases as the encoding tests in `engine/src/models.rs`, so the two can't drift apart."""

import unittest

from encoding import BYTE_OFFSET, PAD_ID, VALUE_END_ID, VALUE_START_ID, encode_value, line_bounds


def shown(ids: list[int]) -> str:
    special = {PAD_ID: "_", VALUE_START_ID: "[", VALUE_END_ID: "]"}
    return "".join(special.get(i) or chr(i - BYTE_OFFSET) for i in ids)


class EncodeValueTest(unittest.TestCase):
    def test_a_value_gets_markers_and_an_even_share_of_text_on_each_side(self):
        self.assertEqual(shown(encode_value(b"0123456789KEY0123456789", 10, 13, 11)), "789[KEY]012")

    def test_room_one_side_cannot_use_goes_to_the_other(self):
        self.assertEqual(shown(encode_value(b"KEY0123456789", 0, 3, 11)), "[KEY]012345")
        self.assertEqual(shown(encode_value(b"0123456789KEY", 10, 13, 11)), "456789[KEY]")

    def test_short_text_is_padded_and_long_values_are_cut_short(self):
        self.assertEqual(shown(encode_value(b"a KEY b", 2, 5, 12)), "a [KEY] b___")
        self.assertEqual(shown(encode_value(b"a LONGVALUE b", 2, 11, 6)), "[LONG]")


class LineBoundsTest(unittest.TestCase):
    def test_line_bounds_stop_at_any_line_break(self):
        text = b"a=1\nkey: VALUE # note\r\nb=2"
        self.assertEqual(text[9:14], b"VALUE")
        self.assertEqual(line_bounds(text, 9, 14), (4, 21))
        self.assertEqual(line_bounds(b"VALUE", 0, 5), (0, 5))
        self.assertEqual(line_bounds(b"x\rVALUE\ry", 2, 7), (2, 7))


if __name__ == "__main__":
    unittest.main()
