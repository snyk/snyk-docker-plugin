import { parseDependency } from "../../lib/python-parser/metadata-parser";
import type { PythonRequirement } from "../../lib/python-parser/types";

describe("parseDependency", () => {
  it("parses simple requires-dist content", () => {
    const received = parseDependency("MarkupSafe (>=2.0)", []);
    const expected: PythonRequirement = {
      name: "markupsafe",
      specifier: ">=",
      version: "2.0",
      extras: [],
      extraEnvMarkers: [],
    };
    expect(received).toEqual(expected);
  });

  it("picks first version and specifier when there are multiple", () => {
    const received = parseDependency(
      "pyparsing (!=3.0.0,!=3.0.1,!=3.0.2,!=3.0.3,<4,>=2.4.2)",
      [],
    );
    const expected: PythonRequirement = {
      name: "pyparsing",
      specifier: "!=",
      version: "3.0.0",
      extras: [],
      extraEnvMarkers: [],
    };
    expect(received).toEqual(expected);
  });

  it("parses extra environment markers", () => {
    const received = parseDependency('Babel >=0.8 ; extra == "i18n"', ["i18n"]);
    const expected: PythonRequirement = {
      name: "babel",
      specifier: ">=",
      version: "0.8",
      extras: [],
      extraEnvMarkers: ["i18n"],
    };
    expect(received).toEqual(expected);
  });

  it("parses multiple extra environment markers", () => {
    const received = parseDependency(
      'httpx (>=0.16.0,<0.17.0); extra == "client" or extra == "full"',
      ["client", "full"],
    );
    const expected: PythonRequirement = {
      name: "httpx",
      specifier: ">=",
      version: "0.16.0",
      extras: [],
      extraEnvMarkers: ["client", "full"],
    };
    expect(received).toEqual(expected);
  });

  it("ignores unused provides extras when parsing extra environment markers", () => {
    const received = parseDependency(
      'pydantic (>=1.7,<2.0); extra == "full" or extra == "type"',
      ["client", "full", "msgpack", "type"],
    );
    const expected: PythonRequirement = {
      name: "pydantic",
      specifier: ">=",
      version: "1.7",
      extras: [],
      extraEnvMarkers: ["full", "type"],
    };
    expect(received).toEqual(expected);
  });

  it("parses single extra from distribution", () => {
    const received = parseDependency(
      'uvicorn[standard]>=0.12.0; extra == "all"',
      ["all"],
    );
    const expected: PythonRequirement = {
      name: "uvicorn",
      specifier: ">=",
      version: "0.12.0",
      extras: ["standard"],
      extraEnvMarkers: ["all"],
    };
    expect(received).toEqual(expected);
  });

  it("parses multiple extra from distribution", () => {
    const received = parseDependency(
      "hdfs[avro,dataframe,kerberos] (>=2.0.4) ; extra == 'all'",
      ["all"],
    );
    const expected: PythonRequirement = {
      name: "hdfs",
      specifier: ">=",
      version: "2.0.4",
      extras: ["avro", "dataframe", "kerberos"],
      extraEnvMarkers: ["all"],
    };
    expect(received).toEqual(expected);
  });

  it("returns null when dependency string doesn't match expected format", () => {
    const received = parseDependency("!@#$%^&*()", []);
    expect(received).toBeNull();
  });

  it("returns null when dependency is empty", () => {
    const received = parseDependency("", []);
    expect(received).toBeNull();
  });

  it("returns null when dependency starts with invalid characters", () => {
    const received = parseDependency("   ; malformed", []);
    expect(received).toBeNull();
  });
});
