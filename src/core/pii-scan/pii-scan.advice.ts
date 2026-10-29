import type { PiiSource } from "./pii-scan.source.ts";

/**
 * why these words: personal data in a query result is legitimate, so the advice there is about analysing without it;
 * anywhere else it is a defect, so the advice is the fix. Either way it hands the work back to the operator when it
 * is outside the task, so the advice cannot hijack a turn.
 */
const ADVICE: Record<PiiSource, string> = {
  "db-query":
    "Personal values were pseudonymised. To analyse them, aggregate in the query (count, GROUP BY, DISTINCT), select only the columns the task needs, add LIMIT, or run a script that reads the rows and prints only statistics. Pseudonyms are stable: equal values share a token, so joins and duplicates still show.",
  "api-response":
    "Personal values were pseudonymised. Request only the fields the task needs; to analyse many records, process them in a script and print only aggregates. Pseudonyms are stable across reads.",
  "data-file":
    "This file holds personal data. Analyse it with a script that prints only aggregates, and keep real exports out of the repository — use a fixture with reserved domains, invalid-checksum documents and test card numbers.",
  log: "A log carrying personal data means code logs it. Fix the code that writes it: log an internal id or a keyed hash instead of the value, or turn on the logger's redaction.",
  "source-file":
    "This source file holds personal data. Replace it with a fixture — a reserved domain (example.com, .invalid, .test), an invalid-checksum document, an issuer test card.",
  "config-file":
    "This config holds personal data. Move it out of the file, into the environment or the data store it belongs to, and use a fixture where an example is needed.",
  other:
    "A tool's output carried personal data. It was pseudonymised; find where it came from before relying on the raw values.",
};

export function piiAdvice(source: PiiSource, kinds: readonly string[], subject: string): string {
  const names = [...new Set(kinds)].join(", ");
  return [
    `[PII-HYGIENE ${source}] ${subject} exposed ${names}; the values were pseudonymised.`,
    ADVICE[source],
    "Do not try to read the raw values another way. If fixing this is outside your task, tell the operator instead.",
  ].join(" ");
}
