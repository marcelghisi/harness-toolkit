/**
 * invariant: no valid personal value is ever written in this repository as a literal — the write gate this module
 * implements would refuse it, and a checksum-valid document in a test file is someone's document. Every valid value a
 * test needs is assembled here at runtime from an incomplete base.
 */

function mod11(digits: readonly number[], weights: readonly number[]): number {
  const rest = weights.reduce((total, weight, index) => total + weight * (digits[index] ?? 0), 0) % 11;
  return rest < 2 ? 0 : 11 - rest;
}

export function cpf(base9: string): string {
  const digits = [...base9].map(Number);
  digits.push(mod11(digits, [10, 9, 8, 7, 6, 5, 4, 3, 2]));
  digits.push(mod11(digits, [11, 10, 9, 8, 7, 6, 5, 4, 3, 2]));
  const text = digits.join("");
  return `${text.slice(0, 3)}.${text.slice(3, 6)}.${text.slice(6, 9)}-${text.slice(9)}`;
}

export function cnpj(base12: string): string {
  const digits = [...base12].map(Number);
  digits.push(mod11(digits, [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]));
  digits.push(mod11(digits, [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]));
  const text = digits.join("");
  return `${text.slice(0, 2)}.${text.slice(2, 5)}.${text.slice(5, 8)}/${text.slice(8, 12)}-${text.slice(12)}`;
}

export function luhnComplete(prefix: string): string {
  for (let digit = 0; digit <= 9; digit += 1) {
    const candidate = `${prefix}${digit}`;
    let sum = 0;
    [...candidate].reverse().forEach((char, index) => {
      let value = Number(char);
      if (index % 2 === 1) {
        value *= 2;
        if (value > 9) {
          value -= 9;
        }
      }
      sum += value;
    });
    if (sum % 10 === 0) {
      return candidate;
    }
  }
  throw new Error("unreachable");
}

export function grouped(digits: string, size = 4): string {
  return digits.match(new RegExp(`.{1,${size}}`, "g"))?.join(" ") ?? digits;
}

export function iban(country: string, bban: string): string {
  const expanded = `${bban}${country}00`.replace(/[A-Z]/g, (char) => String(char.charCodeAt(0) - 55));
  let remainder = 0;
  for (const digit of expanded) {
    remainder = (remainder * 10 + Number(digit)) % 97;
  }
  const check = String(98 - remainder).padStart(2, "0");
  return grouped(`${country}${check}${bban}`);
}

export function dni(base8: string): string {
  return `${base8}${"TRWAGMYFPDXBNJZSQVHLCKE"[Number(base8) % 23]}`;
}

export function nir(base13: string): string {
  const key = 97n - (BigInt(base13) % 97n);
  return `${base13}${String(key).padStart(2, "0")}`;
}

export function email(local: string, domain: string): string {
  return [local, domain].join("@");
}

export function phone(international: string): string {
  return ["+", international].join("");
}
