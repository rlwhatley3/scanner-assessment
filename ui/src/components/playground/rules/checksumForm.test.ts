import assert from "node:assert/strict";
import { describe, it } from "node:test";
import type { Checksum } from "../api.ts";
import { describeChecksum } from "../checksum.ts";
import { checksumFormFrom, checksumFrom, withCalculation } from "./checksumForm.ts";

describe("checksum form", () => {
  it("round-trips every in-house setup through the form", () => {
    const setups: Checksum[] = [
      { algorithm: "crc32", encoding: "hex", prefixLength: 5, length: 8 },
      {
        algorithm: "check_digit",
        alphabet: "0123456789X",
        weights: [2, 3, 4],
        modulus: 11,
        check: "complement",
        prefixLength: 0,
        length: 1,
      },
      { algorithm: "hash", hash: "md5", bytes: 2, encoding: "digits", prefixLength: 4, length: 5 },
      { algorithm: "marvin32", seed: "MastRW00" },
      { algorithm: "bip39" },
    ];
    for (const setup of setups) {
      assert.deepEqual(checksumFrom(checksumFormFrom(setup)), setup);
    }
    assert.equal(checksumFrom(checksumFormFrom(null)), undefined);
  });

  it("reads weights separated by commas or spaces", () => {
    const form = {
      ...checksumFormFrom(null),
      algorithm: "check_digit" as const,
      weights: "3,1  7",
    };
    const checksum = checksumFrom(form);
    assert.equal(checksum?.algorithm, "check_digit");
    assert.deepEqual(checksum?.algorithm === "check_digit" && checksum.weights, [3, 1, 7]);
  });

  it("picks sizes that fit when the calculation changes", () => {
    const crc32 = withCalculation(checksumFormFrom(null), "crc32");
    assert.equal(withCalculation(crc32, "check_digit").length, "1");
    const hash = withCalculation(crc32, "hash");
    assert.deepEqual([hash.encoding, hash.bytes, hash.length], ["hex", "4", "8"]);
    assert.equal(withCalculation(hash, "hash"), hash);
  });

  it("describes in-house setups in a few words", () => {
    assert.equal(
      describeChecksum({
        algorithm: "hash",
        hash: "sha256",
        bytes: 4,
        encoding: "base62",
        prefixLength: 5,
        length: 6,
      }),
      "SHA-256, base62, last 6 characters",
    );
    assert.equal(
      describeChecksum({
        algorithm: "check_digit",
        alphabet: "0123456789",
        weights: [1],
        modulus: 10,
        check: "remainder",
        prefixLength: 0,
        length: 1,
      }),
      "Check digit, mod 10, last 1 character",
    );
  });
});
