import type { SavedMatch } from "../api.ts";

/** How far ahead a suppression can expire; the API rejects anything later. */
export const MAX_SUPPRESSION_DAYS = 365;

/** How long a new suppression lasts unless the user picks another date. */
export const DEFAULT_SUPPRESSION_DAYS = 30;

/** Indices of the open and the suppressed matches, each in the order given. */
export function splitSuppressed(findings: SavedMatch[]): { open: number[]; suppressed: number[] } {
  const open: number[] = [];
  const suppressed: number[] = [];
  findings.forEach((finding, index) => {
    (finding.suppression ? suppressed : open).push(index);
  });
  return { open, suppressed };
}

/** A local calendar date as `YYYY-MM-DD`, the format a date input uses. */
function localDate(date: Date): string {
  const pad = (value: number) => String(value).padStart(2, "0");
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`;
}

function addDays(date: Date, days: number): Date {
  const result = new Date(date);
  result.setDate(result.getDate() + days);
  return result;
}

/** The dates a suppression can expire on: from tomorrow until a day inside the API's limit, so
 * the end of the last day is still within it. */
export function expiryBounds(now: Date): { min: string; max: string; initial: string } {
  return {
    min: localDate(addDays(now, 1)),
    max: localDate(addDays(now, MAX_SUPPRESSION_DAYS - 1)),
    initial: localDate(addDays(now, DEFAULT_SUPPRESSION_DAYS)),
  };
}

/** The end of a picked local date, as the ISO date-time the API takes. A suppression lasts
 * through the whole day the user picked. */
export function expiryFromDate(date: string): string {
  return new Date(`${date}T23:59:59.999`).toISOString();
}
