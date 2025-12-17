import { isNumber, isStrictNumber, isTrue } from "../../lib/option-utils";

describe("isTrue", () => {
  test("'true' should return true", () => {
    expect(isTrue("true")).toBe(true);
  });

  test("'True' should return true", () => {
    expect(isTrue("True")).toBe(true);
  });

  test("'TRUE' should return true", () => {
    expect(isTrue("TRUE")).toBe(true);
  });

  test("true boolean should return true", () => {
    expect(isTrue(true)).toBe(true);
  });

  test("'false' should return false", () => {
    expect(isTrue("false")).toBe(false);
  });

  test("false boolean should return false", () => {
    expect(isTrue(false)).toBe(false);
  });

  test("'123' should return false", () => {
    expect(isTrue("123")).toBe(false);
  });

  test("undefined should return false", () => {
    expect(isTrue(undefined)).toBe(false);
  });
});

describe("isNumber", () => {
  test("'123' should return true", () => {
    expect(isNumber("123")).toBe(true);
  });

  test("'abc' should return false", () => {
    expect(isNumber("abc")).toBe(false);
  });

  test("'' should return true", () => {
    expect(isNumber("")).toBe(true);
  });

  test("true should return true", () => {
    expect(isNumber(true)).toBe(true);
  });

  test("false should return true", () => {
    expect(isNumber(false)).toBe(true);
  });

  test("undefined should return false", () => {
    expect(isNumber(undefined)).toBe(false);
  });

  test("'Infinity' should return true", () => {
    expect(isNumber("Infinity")).toBe(true);
  });

  test("'100px' should return false", () => {
    expect(isNumber("100px")).toBe(false);
  });

  test("'1s00' should return false", () => {
    expect(isNumber("1s00")).toBe(false);
  });

  test("'123.45' should return true", () => {
    expect(isNumber("123.45")).toBe(true);
  });

  test("'0.5' should return true", () => {
    expect(isNumber("0.5")).toBe(true);
  });

  test("'-123.45' should return true", () => {
    expect(isNumber("-123.45")).toBe(true);
  });

  test("'.5' should return true", () => {
    expect(isNumber(".5")).toBe(true);
  });

  test("'123.' should return true", () => {
    expect(isNumber("123.")).toBe(true);
  });
});

describe("isStrictNumber", () => {
  test("'123' should return true", () => {
    expect(isStrictNumber("123")).toBe(true);
  });

  test("'abc' should return false", () => {
    expect(isStrictNumber("abc")).toBe(false);
  });

  test("'' should return false", () => {
    expect(isStrictNumber("")).toBe(false);
  });

  test("true should return false", () => {
    expect(isStrictNumber(true)).toBe(false);
  });

  test("false should return false", () => {
    expect(isStrictNumber(false)).toBe(false);
  });

  test("undefined should return false", () => {
    expect(isStrictNumber(undefined)).toBe(false);
  });

  test("'Infinity' should return false", () => {
    expect(isStrictNumber("Infinity")).toBe(false);
  });

  test("'true' should return false", () => {
    expect(isStrictNumber("true")).toBe(false);
  });

  test("'100s' should return false", () => {
    expect(isStrictNumber("100s")).toBe(false);
  });

  test("'1s00' should return false", () => {
    expect(isStrictNumber("1s00")).toBe(false);
  });

  test("'s100' should return false", () => {
    expect(isStrictNumber("s100")).toBe(false);
  });

  test("'123.45' should return true", () => {
    expect(isStrictNumber("123.45")).toBe(true);
  });

  test("'0.5' should return true", () => {
    expect(isStrictNumber("0.5")).toBe(true);
  });

  test("'-123.45' should return true", () => {
    expect(isStrictNumber("-123.45")).toBe(true);
  });

  test("'.5' should return true", () => {
    expect(isStrictNumber(".5")).toBe(true);
  });

  test("'123.' should return true", () => {
    expect(isStrictNumber("123.")).toBe(true);
  });

  test("'   ' should return false", () => {
    expect(isStrictNumber("   ")).toBe(false);
  });

  test("' 1' should return true", () => {
    expect(isStrictNumber(" 1")).toBe(true);
  });

  test("'1  ' should return true", () => {
    expect(isStrictNumber("1  ")).toBe(true);
  });

  test("'. . 234 ' should return false", () => {
    expect(isStrictNumber(". . 234 ")).toBe(false);
  });
});
