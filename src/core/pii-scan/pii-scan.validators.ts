/**
 * invariant: the checksums a personal-data detector may require are a closed set. A project template names one of these by key and never supplies code, so a template is
 * data the harness reads, not a program it runs.
 *
 * why checksums at all: a bare run of digits is an order number as often as it is a document. Requiring the check
 * digit to agree turns "eleven digits" into "a CPF" with roughly a 1-in-100 chance of a coincidence.
 */

function digitsOf(text: string): number[] {
  return [...text].filter((char) => char >= "0" && char <= "9").map(Number);
}

function allSame(digits: readonly number[]): boolean {
  return digits.every((digit) => digit === digits[0]);
}

export function luhn(text: string): boolean {
  const digits = digitsOf(text);
  if (digits.length < 2) {
    return false;
  }
  let sum = 0;
  for (let index = 0; index < digits.length; index += 1) {
    const fromRight = digits.length - 1 - index;
    let digit = digits[index] ?? 0;
    if (fromRight % 2 === 1) {
      digit *= 2;
      if (digit > 9) {
        digit -= 9;
      }
    }
    sum += digit;
  }
  return sum % 10 === 0;
}

// why: an IBAN's check digits are a mod-97 remainder over the rearranged, letter-expanded string — ISO 13616.
export function mod97(text: string): boolean {
  const compact = text.replace(/\s+/g, "").toUpperCase();
  if (!/^[A-Z]{2}\d{2}[A-Z0-9]{10,30}$/.test(compact)) {
    return false;
  }
  const rearranged = `${compact.slice(4)}${compact.slice(0, 4)}`;
  let remainder = 0;
  for (const char of rearranged) {
    const value = char >= "A" && char <= "Z" ? String(char.charCodeAt(0) - 55) : char;
    for (const digit of value) {
      remainder = (remainder * 10 + Number(digit)) % 97;
    }
  }
  return remainder === 1;
}

function mod11Digit(digits: readonly number[], weights: readonly number[]): number {
  const sum = weights.reduce((total, weight, index) => total + weight * (digits[index] ?? 0), 0);
  const rest = sum % 11;
  return rest < 2 ? 0 : 11 - rest;
}

export function brCpf(text: string): boolean {
  const digits = digitsOf(text);
  if (digits.length !== 11 || allSame(digits)) {
    return false;
  }
  const first = mod11Digit(digits, [10, 9, 8, 7, 6, 5, 4, 3, 2]);
  const second = mod11Digit(digits, [11, 10, 9, 8, 7, 6, 5, 4, 3, 2]);
  return digits[9] === first && digits[10] === second;
}

export function brCnpj(text: string): boolean {
  const digits = digitsOf(text);
  if (digits.length !== 14 || allSame(digits)) {
    return false;
  }
  const first = mod11Digit(digits, [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
  const second = mod11Digit(digits, [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]);
  return digits[12] === first && digits[13] === second;
}

export function ptNif(text: string): boolean {
  const digits = digitsOf(text);
  if (digits.length !== 9 || !"125689".includes(String(digits[0]))) {
    return false;
  }
  const sum = digits.slice(0, 8).reduce((total, digit, index) => total + digit * (9 - index), 0);
  const check = 11 - (sum % 11);
  return digits[8] === (check >= 10 ? 0 : check);
}

const DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE";

// why: a DNI is eight digits and the letter their remainder picks; an NIE swaps the first digit for X, Y or Z.
export function esDni(text: string): boolean {
  const compact = text.replace(/[\s-]/g, "").toUpperCase();
  const match = /^([XYZ]?)(\d{7,8})([A-Z])$/.exec(compact);
  if (!match) {
    return false;
  }
  const prefix = match[1] ? String("XYZ".indexOf(match[1])) : "";
  const number = Number(`${prefix}${match[2]}`);
  return DNI_LETTERS[number % 23] === match[3];
}

// why: a French NIR is thirteen digits and a two-digit key equal to 97 minus their remainder; Corsica's 2A/2B
// department is folded to digits first.
export function frNir(text: string): boolean {
  const compact = text.replace(/\s+/g, "").toUpperCase().replace("2A", "19").replace("2B", "18");
  if (!/^\d{15}$/.test(compact)) {
    return false;
  }
  const body = BigInt(compact.slice(0, 13));
  return 97n - (body % 97n) === BigInt(compact.slice(13));
}

const VERHOEFF_D = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
  [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
  [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
  [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
  [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
  [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
  [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
  [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
  [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];
const VERHOEFF_P = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
  [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
  [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
  [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
  [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
  [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
  [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
  [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

// why: Aadhaar numbers carry a Verhoeff check digit and never start with 0 or 1.
export function verhoeff(text: string): boolean {
  const digits = digitsOf(text);
  if (digits.length !== 12 || digits[0] === 0 || digits[0] === 1) {
    return false;
  }
  let check = 0;
  for (let index = 0; index < digits.length; index += 1) {
    const digit = digits[digits.length - 1 - index] ?? 0;
    check = VERHOEFF_D[check]?.[VERHOEFF_P[index % 8]?.[digit] ?? 0] ?? 0;
  }
  return check === 0;
}

export function arCuit(text: string): boolean {
  const digits = digitsOf(text);
  if (digits.length !== 11) {
    return false;
  }
  const weights = [5, 4, 3, 2, 7, 6, 5, 4, 3, 2];
  const sum = weights.reduce((total, weight, index) => total + weight * (digits[index] ?? 0), 0);
  const rest = 11 - (sum % 11);
  const check = rest === 11 ? 0 : rest === 10 ? 9 : rest;
  return digits[10] === check;
}

export function auTfn(text: string): boolean {
  const digits = digitsOf(text);
  if (digits.length !== 9) {
    return false;
  }
  const weights = [1, 4, 3, 7, 5, 8, 6, 9, 10];
  return weights.reduce((total, weight, index) => total + weight * (digits[index] ?? 0), 0) % 11 === 0;
}

// why: E.164 allows at most fifteen digits, and fewer than eight is a short code or a version string, not a phone.
export function e164(text: string): boolean {
  const count = digitsOf(text).length;
  return count >= 8 && count <= 15;
}

// why: a card is a known issuer prefix, a card-length run and a Luhn digit together — Luhn alone passes one random
// number in ten.
const CARD_PREFIX = /^(4|5[1-5]|2[2-7]|3[47]|6011|65|64[4-9]|35|30[0-5]|36|38|62)/;

export function card(text: string): boolean {
  const digits = digitsOf(text).join("");
  return digits.length >= 13 && digits.length <= 19 && CARD_PREFIX.test(digits) && luhn(digits);
}

export const VALIDATORS = {
  luhn,
  e164,
  card,
  mod97,
  "br-cpf": brCpf,
  "br-cnpj": brCnpj,
  "pt-nif": ptNif,
  "es-dni": esDni,
  "fr-nir": frNir,
  verhoeff,
  "ar-cuit": arCuit,
  "au-tfn": auTfn,
} as const;

export type ValidatorName = keyof typeof VALIDATORS;

export function isValidatorName(name: string): name is ValidatorName {
  return Object.hasOwn(VALIDATORS, name);
}
