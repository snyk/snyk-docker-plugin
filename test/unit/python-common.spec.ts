import { specifierValidRange } from "../../lib/python-parser/common";

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
