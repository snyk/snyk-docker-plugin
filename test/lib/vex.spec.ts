import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { VexStatement, VexStatementsFact } from "../../lib/facts";
import { PluginResponse, ScanResult } from "../../lib/types";
import { attachVexFactsToScanResults } from "../../lib/vex";
import { loadVexDocument, MAX_VEX_BYTES } from "../../lib/vex/loader";
import { parseVexDocument, VEX_LIMITS } from "../../lib/vex/parser";

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
    scanResults: Array.from({ length: numResults }, (_, i) =>
      makeScanResult(i),
    ),
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
            affects: [
              {
                /* no ref */
              },
            ],
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
      expect(() => parseVexDocument({})).toThrow(
        "Unrecognized VEX document format",
      );
    });

    it("throws on null input", () => {
      expect(() => parseVexDocument(null)).toThrow(
        "Unrecognized VEX document format",
      );
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

  it("rejects local files larger than MAX_VEX_BYTES without reading them", async () => {
    const filePath = path.join(tmpDir, "huge.json");
    // Create a sparse file just past the cap; ftruncate avoids actually
    // writing the bytes so the test stays fast.
    const fd = fs.openSync(filePath, "w");
    try {
      fs.ftruncateSync(fd, MAX_VEX_BYTES + 1);
    } finally {
      fs.closeSync(fd);
    }

    await expect(loadVexDocument(filePath)).rejects.toThrow(
      /exceeds maximum size/,
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
    const { response: withVex, warnings } = await attachVexFactsToScanResults(
      response,
      filePath,
    );

    expect(warnings).toEqual([]);
    expect(withVex.scanResults).toHaveLength(2);

    for (const result of withVex.scanResults) {
      const vexFact = result.facts.find((f) => f.type === "vexStatements") as
        | VexStatementsFact
        | undefined;
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

    const { response: returned, warnings } = await attachVexFactsToScanResults(
      response,
      nonExistentPath,
    );

    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/Failed to load VEX file/);
    // Original scan results are untouched (no vexStatements facts added)
    for (const result of returned.scanResults) {
      expect(result.facts.every((f) => f.type !== "vexStatements")).toBe(true);
    }
  });

  it("returns the response unchanged and no warning when vexFilePath is undefined", async () => {
    const response = makePluginResponse(2);
    const { response: returned, warnings } = await attachVexFactsToScanResults(
      response,
      undefined,
    );

    expect(warnings).toEqual([]);
    expect(returned).toBe(response); // same reference — nothing changed
  });

  it("returns the response unchanged and no warning when vexFilePath is empty string", async () => {
    const response = makePluginResponse(1);
    const { response: returned, warnings } = await attachVexFactsToScanResults(
      response,
      "",
    );

    expect(warnings).toEqual([]);
    expect(returned).toBe(response);
  });
});

// ─── DoS / size-cap tests ────────────────────────────────────────────────────

describe("parseVexDocument size caps", () => {
  it("truncates OpenVEX statements past the maxStatements cap", () => {
    const overflow = VEX_LIMITS.maxStatements + 50;
    const doc = {
      "@context": "https://openvex.dev/ns/v0.2.0",
      "@id": "test",
      statements: Array.from({ length: overflow }, (_, i) => ({
        vulnerability: `CVE-2024-${i}`,
        products: [`pkg:npm/example@${i}`],
        status: "not_affected",
      })),
    };

    const result = parseVexDocument(doc);

    expect(result.statements).toHaveLength(VEX_LIMITS.maxStatements);
    expect(result.warnings).toContainEqual(
      expect.stringMatching(/statements truncated/),
    );
  });

  it("caps OpenVEX products per statement (no cartesian explosion)", () => {
    const productCount = VEX_LIMITS.maxProductsPerStatement + 100;
    const doc = {
      "@context": "https://openvex.dev/ns/v0.2.0",
      "@id": "test",
      statements: [
        {
          vulnerability: "CVE-2024-0001",
          products: Array.from(
            { length: productCount },
            (_, i) => `pkg:npm/p@${i}`,
          ),
          status: "not_affected",
        },
      ],
    };

    const result = parseVexDocument(doc);

    expect(result.statements).toHaveLength(VEX_LIMITS.maxProductsPerStatement);
  });

  it("caps OpenVEX subcomponents against the per-statement product budget", () => {
    const doc = {
      "@context": "https://openvex.dev/ns/v0.2.0",
      "@id": "test",
      statements: [
        {
          vulnerability: "CVE-2024-0001",
          products: [
            {
              "@id": "pkg:npm/parent@1",
              subcomponents: Array.from(
                { length: VEX_LIMITS.maxSubcomponentsPerProduct + 5_000 },
                (_, i) => ({ "@id": `pkg:npm/sub@${i}` }),
              ),
            },
          ],
          status: "not_affected",
        },
      ],
    };

    const result = parseVexDocument(doc);

    // 1 parent id + at most maxProductsPerStatement total product ids.
    expect(result.statements.length).toBeLessThanOrEqual(
      VEX_LIMITS.maxProductsPerStatement,
    );
  });

  it("bounds total emitted statements when vulnerabilityIds × productIds explodes", () => {
    // Single statement, single vulnerability, productCap products → cap out at
    // exactly maxProductsPerStatement, never the full hypothetical product.
    const doc = {
      "@context": "https://openvex.dev/ns/v0.2.0",
      "@id": "test",
      statements: Array.from({ length: 200 }, (_, statementIndex) => ({
        vulnerability: `CVE-2024-${statementIndex}`,
        products: Array.from(
          { length: VEX_LIMITS.maxProductsPerStatement },
          (_, j) => `pkg:npm/p${statementIndex}@${j}`,
        ),
        status: "affected",
      })),
    };

    const result = parseVexDocument(doc);

    expect(result.statements.length).toBeLessThanOrEqual(
      VEX_LIMITS.maxEmittedStatements,
    );
    expect(result.warnings).toContainEqual(
      expect.stringMatching(/produced more than/),
    );
  });

  it("truncates CycloneDX-VEX vulnerabilities past the maxStatements cap", () => {
    const overflow = VEX_LIMITS.maxStatements + 25;
    const doc = {
      bomFormat: "CycloneDX",
      specVersion: "1.4",
      vulnerabilities: Array.from({ length: overflow }, (_, i) => ({
        id: `CVE-2024-${i}`,
        affects: [{ ref: `pkg:npm/p@${i}` }],
        analysis: { state: "not_affected" },
      })),
    };

    const result = parseVexDocument(doc);

    expect(result.statements).toHaveLength(VEX_LIMITS.maxStatements);
    expect(result.warnings).toContainEqual(
      expect.stringMatching(/vulnerabilities truncated/),
    );
  });
});

describe("attachVexFactsToScanResults surfaces parser warnings", () => {
  let tmpDir: string;

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "vex-warn-test-"));
  });

  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  it("returns parser warnings alongside a populated response", async () => {
    const overflow = VEX_LIMITS.maxStatements + 5;
    const doc = {
      "@context": "https://openvex.dev/ns/v0.2.0",
      "@id": "test",
      statements: Array.from({ length: overflow }, (_, i) => ({
        vulnerability: `CVE-2024-${i}`,
        products: [`pkg:npm/p@${i}`],
        status: "not_affected",
      })),
    };
    const filePath = path.join(tmpDir, "huge.json");
    fs.writeFileSync(filePath, JSON.stringify(doc), "utf8");

    const response = makePluginResponse(1);
    const { response: withVex, warnings } = await attachVexFactsToScanResults(
      response,
      filePath,
    );

    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/truncated/);
    const vexFact = withVex.scanResults[0].facts.find(
      (f) => f.type === "vexStatements",
    ) as VexStatementsFact;
    expect(vexFact.data.statements).toHaveLength(VEX_LIMITS.maxStatements);
  });
});
