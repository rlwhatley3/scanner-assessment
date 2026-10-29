import type { Checksum, ChecksumEncoding, Crc32Checksum, HashFunction } from "./api.ts";

export const CHECKSUM_LABELS: Record<Checksum["algorithm"], string> = {
  crc32: "CRC32 at the end of the token",
  check_digit: "Check digit at the end of the token",
  hash: "Hash at the end of the token",
  luhn: "Luhn check digit (card numbers)",
  base58check: "Base58Check (Bitcoin keys)",
  bech32: "Bech32 (age and Nostr keys)",
  bech32m: "Bech32m (Taproot addresses)",
  bip39: "BIP-39 (crypto wallet seed phrases)",
  marvin32: "Marvin32 (Azure keys)",
  verhoeff: "Verhoeff check digit (Aadhaar numbers)",
  mod11: "Mod 11 check digit (ISBN-10, NHS numbers)",
  mod97: "Mod 97 (IBANs)",
};

/** Seeds for the Azure key kinds; each kind has its own. */
export const MARVIN32_PRESETS: { label: string; seed: string }[] = [
  { label: "Azure Storage", seed: "Default0" },
  { label: "Azure Cosmos DB (read-write)", seed: "MastRW00" },
  { label: "Azure Functions", seed: "Functi00" },
  { label: "Azure Cache for Redis", seed: "Access00" },
  { label: "Azure AI Search (admin)", seed: "PAdmin00" },
  { label: "Azure Container Registry", seed: "ACRDflt0" },
];

export const ENCODING_LABELS: Record<ChecksumEncoding, string> = {
  base62: "Base62 (0-9, A-Z, a-z)",
  base36: "Base36 (0-9, a-z)",
  hex: "Hex (0-9, a-f)",
  digits: "Digits (0-9)",
};

/** The setups a rule author describes piece by piece: which part, how it's calculated, how it's written. */
export const IN_HOUSE_ALGORITHMS = ["crc32", "check_digit", "hash"] as const;
export type InHouseAlgorithm = (typeof IN_HOUSE_ALGORITHMS)[number];

export function isInHouse(algorithm: string): algorithm is InHouseAlgorithm {
  return (IN_HOUSE_ALGORITHMS as readonly string[]).includes(algorithm);
}

export const CALCULATION_LABELS: Record<InHouseAlgorithm, string> = {
  crc32: "CRC32",
  check_digit: "Check digit (a weighted sum)",
  hash: "Hash (SHA-256, SHA-1, or MD5)",
};

export const HASH_LABELS: Record<HashFunction, string> = {
  sha256: "SHA-256",
  sha1: "SHA-1",
  md5: "MD5",
};

/** The fewest characters that hold a full CRC32 in each encoding; the engine's limits. */
export const CRC32_MIN_LENGTH: Record<ChecksumEncoding, number> = {
  base62: 6,
  base36: 7,
  hex: 8,
  digits: 10,
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
  if (checksum.algorithm === "marvin32") {
    const preset = MARVIN32_PRESETS.find(({ seed }) => seed === checksum.seed);
    return `Marvin32 (${preset?.label ?? `seed ${checksum.seed}`})`;
  }
  if (checksum.algorithm === "check_digit") {
    return `Check digit, mod ${checksum.modulus}, last ${checksum.length} character${checksum.length === 1 ? "" : "s"}`;
  }
  if (checksum.algorithm === "hash") {
    return `${HASH_LABELS[checksum.hash]}, ${checksum.encoding}, last ${checksum.length} characters`;
  }
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
