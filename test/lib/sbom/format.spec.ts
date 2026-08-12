import { parseSbomFormat } from "../../../lib/sbom/format";

describe("parseSbomFormat", () => {
  it.each([
    ["cyclonedx1.5+json", "cyclonedx1.5+json"],
    ["  CYCLONEDX1.5+JSON  ", "cyclonedx1.5+json"],
  ])("accepts %s", (input, expected) => {
    expect(parseSbomFormat(input)).toBe(expected);
  });

  it.each([undefined, null, ""])(
    "returns undefined for absent value %p",
    (input) => {
      expect(parseSbomFormat(input)).toBeUndefined();
    },
  );

  it.each(["spdx2.3+json", true, "nonsense"])(
    "rejects unsupported value %p with a message naming the value and cyclonedx1.5+json",
    (input) => {
      expect(() => parseSbomFormat(input)).toThrow(String(input));
      expect(() => parseSbomFormat(input)).toThrow("cyclonedx1.5+json");
    },
  );
});
