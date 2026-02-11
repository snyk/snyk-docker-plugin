export { isTrue, isNumber };

function isTrue(value?: boolean | string): boolean {
  return String(value).toLowerCase() === "true";
}

function isNumber(value?: boolean | string): boolean {
  return !isNaN(Number(value));
}
