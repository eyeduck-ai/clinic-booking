const LETTER_CODE: Record<string, number> = {
  A: 10, B: 11, C: 12, D: 13, E: 14, F: 15, G: 16, H: 17,
  I: 34, J: 18, K: 19, L: 20, M: 21, N: 22, O: 35, P: 23,
  Q: 24, R: 25, S: 26, T: 27, U: 28, V: 29, W: 32, X: 30,
  Y: 31, Z: 33,
};

const WEIGHTS = [8, 7, 6, 5, 4, 3, 2, 1, 1];

export const BOOKING_REF_LENGTH = 8;
export const BOOKING_REF_CHARS = "23456789ABCDEFGHJKLMNPQRSTUVWXYZ";

export function normalizeTWId(value: string): string {
  return value.trim().toUpperCase();
}

export function isValidTWId(value: string, allowResident89 = true): boolean {
  const input = normalizeTWId(value);
  if (!/^[A-Z]\d{9}$/.test(input)) return false;

  const letter = input[0];
  const code = LETTER_CODE[letter];
  if (!code) return false;

  const digits = input.slice(1).split("").map((digit) => Number(digit));
  if (digits.some((digit) => Number.isNaN(digit))) return false;

  const genderCode = digits[0];
  if (allowResident89) {
    if (![1, 2, 8, 9].includes(genderCode)) return false;
  } else if (![1, 2].includes(genderCode)) {
    return false;
  }

  const a1 = Math.floor(code / 10);
  const a2 = code % 10;
  const total = a1 * 1 + a2 * 9 + digits.reduce((sum, digit, index) => {
    return sum + digit * WEIGHTS[index];
  }, 0);

  return total % 10 === 0;
}

export function normalizeBookingRef(value: string): string {
  return value.replace(/\s+/g, "").toUpperCase();
}

export function isValidBookingRef(value: string): boolean {
  const input = normalizeBookingRef(value);
  if (input.length !== BOOKING_REF_LENGTH) return false;
  for (const char of input) {
    if (!BOOKING_REF_CHARS.includes(char)) return false;
  }
  return true;
}

export function generateBookingRef(length = BOOKING_REF_LENGTH): string {
  const chars = BOOKING_REF_CHARS;
  const charsLength = chars.length;
  let result = "";

  if (typeof crypto !== "undefined" && crypto.getRandomValues) {
    const buffer = new Uint8Array(length);
    crypto.getRandomValues(buffer);
    for (let i = 0; i < length; i += 1) {
      result += chars[buffer[i] % charsLength];
    }
    return result;
  }

  for (let i = 0; i < length; i += 1) {
    result += chars[Math.floor(Math.random() * charsLength)];
  }
  return result;
}
