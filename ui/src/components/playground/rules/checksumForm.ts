import type { CheckRule, Checksum, ChecksumEncoding, HashFunction } from "../api.ts";
import { CRC32_PRESETS, type InHouseAlgorithm, MARVIN32_PRESETS } from "../checksum.ts";

/** The checksum part of the rule form, as the inputs hold it. */
export interface ChecksumForm {
  algorithm: Checksum["algorithm"] | "";
  /** Which part is the checksum: the last `length` characters, after skipping `prefixLength`. */
  prefixLength: string;
  length: string;
  /** How CRC32 and hash checksums are written. */
  encoding: ChecksumEncoding;
  seed: string;
  /** Check digit: the characters in order, the weights as typed, the modulus, and the rule. */
  alphabet: string;
  weights: string;
  modulus: string;
  check: CheckRule;
  /** Hash: which one, and how many of its leading bytes are kept. */
  hash: HashFunction;
  bytes: string;
}

const GITHUB_SETUP = CRC32_PRESETS[0].setup;

export function checksumFormFrom(checksum: Checksum | null | undefined): ChecksumForm {
  const form: ChecksumForm = {
    algorithm: checksum?.algorithm ?? "",
    prefixLength: String(GITHUB_SETUP.prefixLength),
    length: String(GITHUB_SETUP.length),
    encoding: GITHUB_SETUP.encoding,
    seed: MARVIN32_PRESETS[0].seed,
    alphabet: "0123456789",
    weights: "1",
    modulus: "10",
    check: "complement",
    hash: "sha256",
    bytes: "4",
  };
  switch (checksum?.algorithm) {
    case "crc32":
      return {
        ...form,
        prefixLength: String(checksum.prefixLength),
        length: String(checksum.length),
        encoding: checksum.encoding,
      };
    case "check_digit":
      return {
        ...form,
        prefixLength: String(checksum.prefixLength),
        length: String(checksum.length),
        alphabet: checksum.alphabet,
        weights: checksum.weights.join(", "),
        modulus: String(checksum.modulus),
        check: checksum.check,
      };
    case "hash":
      return {
        ...form,
        prefixLength: String(checksum.prefixLength),
        length: String(checksum.length),
        encoding: checksum.encoding,
        hash: checksum.hash,
        bytes: String(checksum.bytes),
      };
    case "marvin32":
      return { ...form, seed: checksum.seed };
    default:
      return form;
  }
}

/** Weights as typed ("3, 1" or "3 1"); anything that isn't a whole number is left for the engine to reject. */
function parseWeights(weights: string): number[] {
  return weights
    .split(/[\s,]+/)
    .filter((weight) => weight !== "")
    .map(Number);
}

/** The checksum JSON for the definition, or undefined for none. */
export function checksumFrom(form: ChecksumForm): Checksum | undefined {
  const layout = { prefixLength: Number(form.prefixLength), length: Number(form.length) };
  switch (form.algorithm) {
    case "":
      return undefined;
    case "crc32":
      return { algorithm: "crc32", encoding: form.encoding, ...layout };
    case "check_digit":
      return {
        algorithm: "check_digit",
        alphabet: form.alphabet,
        weights: parseWeights(form.weights),
        modulus: Number(form.modulus),
        check: form.check,
        ...layout,
      };
    case "hash":
      return {
        algorithm: "hash",
        hash: form.hash,
        bytes: Number(form.bytes),
        encoding: form.encoding,
        ...layout,
      };
    case "marvin32":
      return { algorithm: "marvin32", seed: form.seed };
    default:
      return { algorithm: form.algorithm };
  }
}

/**
 * The form after the author picks how the checksum is calculated, with sizes that fit the new
 * choice (a check digit is usually one character; 4 bytes of a hash is 8 hex characters).
 */
export function withCalculation(form: ChecksumForm, algorithm: InHouseAlgorithm): ChecksumForm {
  if (algorithm === form.algorithm) return form;
  switch (algorithm) {
    case "crc32":
      return {
        ...form,
        algorithm,
        encoding: GITHUB_SETUP.encoding,
        length: String(GITHUB_SETUP.length),
      };
    case "check_digit":
      return { ...form, algorithm, length: "1" };
    case "hash":
      return { ...form, algorithm, encoding: "hex", bytes: "4", length: "8" };
  }
}
