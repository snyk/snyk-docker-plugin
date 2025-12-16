export { isTrue, isNumber, isStrictNumber };

function isTrue(value?: boolean | string): boolean {
  return String(value).toLowerCase() === "true";
}

// This strictly follows the ECMAScript Language Specification: https://262.ecma-international.org/5.1/#sec-9.3
function isNumber(value?: boolean | string): boolean {
  return !isNaN(Number(value));
}

// Must be a finite numeric value, excluding booleans, and Infinity
function isStrictNumber(value?: boolean | string): boolean {
  if (typeof value === "boolean" || !value) { return false; }

  const num = Number(value);
  return !Number.isNaN(num) && Number.isFinite(num);
}
