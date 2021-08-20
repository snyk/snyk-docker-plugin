export { isTrue };

function isTrue(value?: boolean | string): boolean {
  return String(value).toLowerCase() === "true";
}
