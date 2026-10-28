import type { Checksum, ChecksumEncoding, Crc32Checksum } from "./api.ts";

export const CHECKSUM_LABELS: Record<Checksum["algorithm"], string> = {
  crc32: "CRC32 at the end of the token",
  luhn: "Luhn check digit (card numbers)",
  base58check: "Base58Check (Bitcoin keys)",
};

export const ENCODING_LABELS: Record<ChecksumEncoding, string> = {
  base62: "Base62 (0-9, A-Z, a-z)",
  base36: "Base36 (0-9, a-z)",
  hex: "Hex (0-9, a-f)",
};

/** The fewest characters that hold a full CRC32 in each encoding; the engine's limits. */
export const CRC32_MIN_LENGTH: Record<ChecksumEncoding, number> = {
  base62: 6,
  base36: 7,
  hex: 8,
};
export const CRC32_MAX_LENGTH = 16;

/** Known CRC32 token setups a rule author can start from. */
export const CRC32_PRESETS: { label: string; setup: Omit<Crc32Checksum, "algorithm"> }[] = [
  {
    label: "GitHub / npm tokens",
    setup: { encoding: "base62", prefixLength: 4, length: 6 },
  },
  {
    label: "GitLab tokens",
    setup: { encoding: "base36", prefixLength: 0, length: 7 },
  },
];

/** A short description for lists and tables, e.g. "CRC32 (GitHub / npm tokens)". */
export function describeChecksum(checksum: Checksum | null | undefined): string | null {
  if (!checksum) return null;
  if (checksum.algorithm !== "crc32") return CHECKSUM_LABELS[checksum.algorithm];
  const preset = CRC32_PRESETS.find(
    ({ setup }) =>
      setup.encoding === checksum.encoding &&
      setup.prefixLength === checksum.prefixLength &&
      setup.length === checksum.length,
  );
  return preset
    ? `CRC32 (${preset.label})`
    : `CRC32, ${checksum.encoding}, last ${checksum.length} characters`;
}
