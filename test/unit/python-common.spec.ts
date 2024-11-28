import {
  compareVersions,
  parseExtraNames,
  specifierValidRange,
  VERSION_EXTRACTION_REGEX,
} from "../../lib/python-parser/common";

describe("python version specifier parsing", () => {
  it("makes no change when change is not necessary", () => {
    expect(specifierValidRange("<", "1.0.0")).toEqual("<");
    expect(specifierValidRange("<=", "1.0.0")).toEqual("<=");
    expect(specifierValidRange("!=", "1.0.0")).toEqual("!=");
    expect(specifierValidRange(">=", "1.0.0")).toEqual(">=");
    expect(specifierValidRange(">", "1.0.0")).toEqual(">");
  });

  it("changes multiple equal signs", () => {
    expect(specifierValidRange("==", "1.0.0")).toEqual("=");
    expect(specifierValidRange("===", "1.0.0")).toEqual("=");
  });

  it("changes compatible release", () => {
    expect(specifierValidRange("~=", "1.2")).toEqual("^");
    expect(specifierValidRange("~=", "1.2.3")).toEqual("~");
  });
});

describe("The regex should correctly group the versions", () => {
  test.each([
    ["1", "1"],
    ["1.2", "1.2"],
    ["11.34.56", "11.34.56"],
    ["2.4.6.7", "2.4.6.7"],
    ["3.4.5-f", "3.4.5"],
    ["3.4.5-fds.3.34", "3.4.5"],
    ["3.-4.4", "3"],
  ])("Version String %s should become %s", (version, expected) => {
    expect(VERSION_EXTRACTION_REGEX.exec(version)!.groups!.VERSION).toBe(
      expected,
    );
  });

  test("Version String sfd should not match", () => {
    expect(VERSION_EXTRACTION_REGEX.exec("sfd")).toBeNull();
  });
});

describe("compareVersions should support multiple compare groups", () => {
  test.each([
    ["1", "2", 1],
    ["1.2", "1.5", 1],
    ["11.999.56", "11.34.56", -1],
    ["2.4.6.8", "2.4.6.7", -1],
    ["3.4.5-f", "3.4.19-fjk", 1],
    ["3.4.5-fds.99.34", "4.4.5", 1],
    ["3.-4.4", "3", 0],
    ["dfhjls", "442.6.43", 0],
    ["dfhjls", "ads", 0],
    ["dfhjls", "", 0],
  ])(
    "Version String %s when compared to %s should be %i",
    (version1, version2, expected) => {
      expect(compareVersions(version1, version2)).toBe(expected);
    },
  );
  test("Correctly sorts in descending order", () => {
    expect(["1", "2", "3.4", "1.4"].sort(compareVersions)).toEqual([
      "3.4",
      "2",
      "1.4",
      "1",
    ]);
  });
});

describe("python extras parsing", () => {
  it("parses single extra", () => {
    expect(parseExtraNames("one")).toEqual(["one"]);
  });
  it("parses multiple extras", () => {
    expect(parseExtraNames("one,two,three")).toEqual(["one", "two", "three"]);
  });
  it("handles whitespace when parsing single extra", () => {
    expect(parseExtraNames(" one ")).toEqual(["one"]);
  });
  it("handles whitespace when parsing multiple extras", () => {
    expect(parseExtraNames(" one ,two ,")).toEqual(["one", "two"]);
  });
  it("no extras when empty", () => {
    expect(parseExtraNames("")).toEqual([]);
  });
  it("no extras when only whitespace", () => {
    expect(parseExtraNames(" ,  ")).toEqual([]);
  });
});
