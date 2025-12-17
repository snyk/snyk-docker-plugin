import { PluginOptions } from './types'; 
export { isTrue, isNumber, isStrictNumber };

function isTrue(value?: boolean | string): boolean {
  return String(value).toLowerCase() === "true";
}

// This strictly follows the ECMAScript Language Specification: https://262.ecma-international.org/5.1/#sec-9.3
function isNumber(value?: boolean | string): boolean {
  return !isNaN(Number(value));
}

// Must be a finite numeric value, excluding booleans, Infinity, and non-numeric strings
function isStrictNumber(value?: boolean | string): boolean {
  if (typeof value === "boolean" || !value?.replace(/\s/g, "").length) {
    return false;
  }

  const num = Number(value);
  return Number.isFinite(num);
}

export function resolveNestedJarsOption(options?: Partial<PluginOptions>) {
  const safeOptions = options || {}; 

  return [
    safeOptions['nested-jars-depth'],
    safeOptions['shaded-jars-depth'],
  ].find((val) => val !== '' && val != null);
}
