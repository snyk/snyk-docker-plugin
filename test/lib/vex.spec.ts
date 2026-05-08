import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { loadVexDocument } from "../../lib/vex/loader";
import { parseVexDocument } from "../../lib/vex/parser";
import { attachVexFactsToScanResults } from "../../lib/vex";
import { VexStatementsFact, VexStatement } from "../../lib/facts";
import { PluginResponse, ScanResult } from "../../lib/types";

// ─── Fixtures ────────────────────────────────────────────────────────────────

const MINIMAL_OPENVEX_DOC = {
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/1",
  statements: [
    {
      vulnerability: { name: "CVE-2024-0001" },
      products: ["pkg:npm/example@1.0.0"],
      status: "not_affected",
      justification: "vulnerable_code_not_in_execute_path",
    },
  ],
};

const OPENVEX_WITH_STRING_VULN = {
  "@context": "https://openvex.dev/ns/v0.2.0",
  "@id": "https://example.com/vex/2",
  statements: [
    {
      vulnerability: "CVE-2024-9999",
      products: ["pkg:deb/libc6@2.31"],
      status: "affected",
    },
  ],
};

const MINIMAL_CYCLONEDX_VEX_DOC = {
  bomFormat: "CycloneDX",
  specVersion: "1.4",
  vulnerabilities: [
    {
      id: "CVE-2024-1234",
      affects: [{ ref: "pkg:npm/lodash@4.17.21" }],
      analysis: { state: "not_affected", justification: "code_not_reachable" },
    },
  ],
};

function makePluginResponse(numResults = 2): PluginResponse {
  const makeScanResult = (i: number): ScanResult => ({
    target: { image: `image${i}:latest` },
    identity: { type: "deb" },
    facts: [{ type: "imageId", data: `sha256:abc${i}` }],
  });
  return {
    scanResults: Array.from({ length: numResults }, (_, i) => makeScanResult(i)),
  };
}

// ─── parseVexDocument tests ───────────────────────────────────────────────────

describe("parseVexDocument", () => {
  describe("OpenVEX format", () => {
    it("parses a minimal OpenVEX document with object vulnerability", () => {
      const result = parseVexDocument(MINIMAL_OPENVEX_DOC);

      expect(result.format).toBe("openvex");
      expect(result.statements).toHaveLength(1);
      const stmt = result.statements[0];
      expect(stmt.vulnerabilityId).toBe("CVE-2024-0001");
      expect(stmt.productId).toBe("pkg:npm/example@1.0.0");
      expect(stmt.status).toBe("not_affected");
      expect(stmt.justification).toBe("vulnerable_code_not_in_execute_path");
    });

    it("parses an OpenVEX document with vulnerability as a plain string", () => {
      const result = parseVexDocument(OPENVEX_WITH_STRING_VULN);

      expect(result.format).toBe("openvex");
      expect(result.statements).toHaveLength(1);
      expect(result.statements[0].vulnerabilityId).toBe("CVE-2024-9999");
      expect(result.statements[0].productId).toBe("pkg:deb/libc6@2.31");
      expect(result.statements[0].status).toBe("affected");
    });

    it("filters out statements missing a vulnerabilityId", () => {
      const doc = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "test",
        statements: [
          {
            // No vulnerability field
            products: ["pkg:npm/example@1.0.0"],
            status: "not_affected",
          },
        ],
      };
      const result = parseVexDocument(doc);
      expect(result.statements).toHaveLength(0);
    });

    it("filters out statements missing a productId", () => {
      const doc = {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "test",
        statements: [
          {
            vulnerability: { name: "CVE-2024-0001" },
            products: [], // empty products → no productIds
            status: "not_affected",
          },
        ],
      };
      const result = parseVexDocument(doc);
      expect(result.statements).toHaveLength(0);
    });
  });

  describe("CycloneDX-VEX format", () => {
    it("parses a minimal CycloneDX-VEX document", () => {
      const result = parseVexDocument(MINIMAL_CYCLONEDX_VEX_DOC);

      expect(result.format).toBe("cyclonedx-vex");
      expect(result.statements).toHaveLength(1);
      const stmt = result.statements[0];
      expect(stmt.vulnerabilityId).toBe("CVE-2024-1234");
      expect(stmt.productId).toBe("pkg:npm/lodash@4.17.21");
      expect(stmt.status).toBe("not_affected");
      expect(stmt.justification).toBe("code_not_reachable");
    });

    it.each<[string, string]>([
      ["exploitable", "affected"],
      ["resolved", "fixed"],
      ["resolved_with_pedigree", "fixed"],
      ["in_triage", "under_investigation"],
      ["false_positive", "not_affected"],
      ["not_affected", "not_affected"],
    ])(
      "maps CycloneDX analysis.state '%s' to VexStatus '%s'",
      (state, expectedStatus) => {
        const doc = {
          bomFormat: "CycloneDX",
          specVersion: "1.4",
          vulnerabilities: [
            {
              id: "CVE-2024-0001",
              affects: [{ ref: "pkg:npm/example@1.0.0" }],
              analysis: { state },
            },
          ],
        };
        const result = parseVexDocument(doc);
        expect(result.statements[0].status).toBe(expectedStatus);
      },
    );

    it("filters out vulnerabilities missing an id", () => {
      const doc = {
        bomFormat: "CycloneDX",
        specVersion: "1.4",
        vulnerabilities: [
          {
            // No id field
            affects: [{ ref: "pkg:npm/example@1.0.0" }],
            analysis: { state: "not_affected" },
          },
        ],
      };
      const result = parseVexDocument(doc);
      expect(result.statements).toHaveLength(0);
    });

    it("filters out affects entries missing a ref", () => {
      const doc = {
        bomFormat: "CycloneDX",
        specVersion: "1.4",
        vulnerabilities: [
          {
            id: "CVE-2024-0001",
            affects: [{ /* no ref */ }],
            analysis: { state: "not_affected" },
          },
        ],
      };
      const result = parseVexDocument(doc);
      expect(result.statements).toHaveLength(0);
    });
  });

  describe("error handling", () => {
    it("throws on an empty object (unrecognized format)", () => {
      expect(() => parseVexDocument({})).toThrow("Unrecognized VEX document format");
    });

    it("throws on null input", () => {
      expect(() => parseVexDocument(null)).toThrow("Unrecognized VEX document format");
    });

    it("throws on a string input", () => {
      expect(() => parseVexDocument("not an object")).toThrow(
        "Unrecognized VEX document format",
      );
    });

    it("throws on a document with bomFormat but no vulnerabilities array", () => {
      expect(() =>
        parseVexDocument({ bomFormat: "CycloneDX", vulnerabilities: "wrong" }),
      ).toThrow("Unrecognized VEX document format");
    });
  });
});

// ─── loadVexDocument tests ────────────────────────────────────────────────────

describe("loadVexDocument", () => {
  let tmpDir: string;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vex-test-"));
  });

  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("reads and parses a valid local JSON file", async () => {
    const filePath = path.join(tmpDir, "valid.json");
    const docContent = { bomFormat: "CycloneDX", vulnerabilities: [] };
    fs.writeFileSync(filePath, JSON.stringify(docContent), "utf8");

    const { raw, source } = await loadVexDocument(filePath);

    expect(source).toBe(filePath);
    expect(raw).toEqual(docContent);
  });

  it("throws with a descriptive message for a missing local file", async () => {
    const missingPath = path.join(tmpDir, "does-not-exist.json");

    await expect(loadVexDocument(missingPath)).rejects.toThrow(
      /Failed to read VEX file/,
    );
  });

  it("throws with a descriptive message for a local file with invalid JSON", async () => {
    const filePath = path.join(tmpDir, "invalid.json");
    fs.writeFileSync(filePath, "{ not valid json }", "utf8");

    await expect(loadVexDocument(filePath)).rejects.toThrow(
      /Failed to parse VEX file/,
    );
  });
});

// ─── attachVexFactsToScanResults tests ───────────────────────────────────────

describe("attachVexFactsToScanResults", () => {
  let tmpDir: string;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vex-attach-test-"));
  });

  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("attaches the same vexStatements fact to every scan result", async () => {
    const filePath = path.join(tmpDir, "openvex.json");
    fs.writeFileSync(filePath, JSON.stringify(MINIMAL_OPENVEX_DOC), "utf8");

    const response = makePluginResponse(2);
    const { response: withVex, warning } = await attachVexFactsToScanResults(
      response,
      filePath,
    );

    expect(warning).toBeUndefined();
    expect(withVex.scanResults).toHaveLength(2);

    for (const result of withVex.scanResults) {
      const vexFact = result.facts.find(
        (f) => f.type === "vexStatements",
      ) as VexStatementsFact | undefined;
      expect(vexFact).toBeDefined();
      expect(vexFact!.data.source).toBe(filePath);
      expect(vexFact!.data.format).toBe("openvex");
      expect(vexFact!.data.statements).toHaveLength(1);
      const stmt = vexFact!.data.statements[0] as VexStatement;
      expect(stmt.vulnerabilityId).toBe("CVE-2024-0001");
      expect(stmt.status).toBe("not_affected");
    }
  });

  it("returns warning and leaves response unchanged for a non-existent file", async () => {
    const nonExistentPath = path.join(tmpDir, "no-such-file.json");
    const response = makePluginResponse(2);

    const { response: returned, warning } = await attachVexFactsToScanResults(
      response,
      nonExistentPath,
    );

    expect(warning).toBeDefined();
    expect(warning).toMatch(/Failed to load VEX file/);
    // Original scan results are untouched (no vexStatements facts added)
    for (const result of returned.scanResults) {
      expect(result.facts.every((f) => f.type !== "vexStatements")).toBe(true);
    }
  });

  it("returns the response unchanged and no warning when vexFilePath is undefined", async () => {
    const response = makePluginResponse(2);
    const { response: returned, warning } = await attachVexFactsToScanResults(
      response,
      undefined,
    );

    expect(warning).toBeUndefined();
    expect(returned).toBe(response); // same reference — nothing changed
  });

  it("returns the response unchanged and no warning when vexFilePath is empty string", async () => {
    const response = makePluginResponse(1);
    const { response: returned, warning } = await attachVexFactsToScanResults(
      response,
      "",
    );

    expect(warning).toBeUndefined();
    expect(returned).toBe(response);
  });
});
