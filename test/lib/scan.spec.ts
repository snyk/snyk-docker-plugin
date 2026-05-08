import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { VexStatementsFact } from "../../lib/facts";
import {
  appendLatestTagIfMissing,
  mergeEnvVarsIntoCredentials,
  scan,
} from "../../lib/scan";
import { PluginResponse, ScanResult } from "../../lib/types";

// Mock the static analysis module so scan() doesn't touch Docker daemon.
jest.mock("../../lib/static", () => ({
  analyzeStatically: jest.fn(),
}));
import * as staticModule from "../../lib/static";

describe("mergeEnvVarsIntoCredentials", () => {
  const oldEnvVars = { ...process.env };
  const FLAG_USER = "flagUser";
  const ENV_VAR_USER = "envVarUser";
  const FLAG_PASSWORD = "flagPassword";
  const ENV_VAR_PASSWORD = "envVarPassword";

  beforeEach(() => {
    delete process.env.SNYK_REGISTRY_USERNAME;
    delete process.env.SNYK_REGISTRY_PASSWORD;
  });

  afterEach(() => {
    process.env = { ...oldEnvVars };
  });

  // prettier-ignore
  it.each`
    
    usernameFlag | usernameEnvVar  |  expectedUsername 
    
    ${undefined} | ${undefined}    |  ${undefined}
    ${FLAG_USER} | ${undefined}    |  ${FLAG_USER}   
    ${undefined} | ${ENV_VAR_USER} |  ${ENV_VAR_USER}
    ${FLAG_USER} | ${ENV_VAR_USER} |  ${FLAG_USER}
        
  `("should set username to $expectedUsername when flag is $usernameFlag and envvar is $usernameEnvVar",
  ({
        usernameFlag,
        usernameEnvVar,
        expectedUsername,
      }) => {
        if (usernameEnvVar) {
            process.env.SNYK_REGISTRY_USERNAME = usernameEnvVar;
        }
        const options = {
            username: usernameFlag,
        };

        mergeEnvVarsIntoCredentials(options);

        expect(options.username).toEqual(expectedUsername);
  });

  // prettier-ignore
  it.each`
    
    passwordFlag     | passwordEnvVar      |  expectedPassword 
    
    ${undefined}     | ${undefined}        | ${undefined}
    ${FLAG_PASSWORD} | ${undefined}        | ${FLAG_PASSWORD}   
    ${undefined}     | ${ENV_VAR_PASSWORD} | ${ENV_VAR_PASSWORD}
    ${FLAG_PASSWORD} | ${ENV_VAR_PASSWORD} | ${FLAG_PASSWORD}
        
  `("should set password to $expectedPassword when flag is $passwordFlag and envvar is $passwordEnvVar",
    ({
       passwordFlag,
       passwordEnvVar,
       expectedPassword,
     }) => {
      if (passwordEnvVar) {
        process.env.SNYK_REGISTRY_PASSWORD = passwordEnvVar;
      }
      const options = {
        password: passwordFlag,
      };

      mergeEnvVarsIntoCredentials(options);

      expect(options.password).toEqual(expectedPassword);
    });
});

describe("appendLatestTagIfMissing", () => {
  it("does not append latest to docker archive path", () => {
    const dockerArchivePath = "docker-archive:some/path/image.tar";
    expect(appendLatestTagIfMissing(dockerArchivePath)).toEqual(
      dockerArchivePath,
    );
  });

  it("does not append latest to docker archive path", () => {
    const ociArchivePath = "oci-archive:some/path/image.tar";
    expect(appendLatestTagIfMissing(ociArchivePath)).toEqual(ociArchivePath);
  });

  it("does not append latest if tag exists", () => {
    const imageWithTag = "image:sometag";
    expect(appendLatestTagIfMissing(imageWithTag)).toEqual(imageWithTag);
  });

  it("does not modify targetImage with sha", () => {
    const imageWithSha =
      "snyk container test nginx@sha256:56ea7092e72db3e9f84d58d583370d59b842de02ea9e1f836c3f3afc7ce408c1";
    expect(appendLatestTagIfMissing(imageWithSha)).toEqual(imageWithSha);
  });

  it("appends latest if no tag exists", () => {
    const imageWithoutTag = "image";
    expect(appendLatestTagIfMissing(imageWithoutTag)).toEqual(
      `${imageWithoutTag}:latest`,
    );
  });
});

// ─── scan() with vexFilePath ──────────────────────────────────────────────────

describe("scan with vexFilePath", () => {
  let tmpDir: string;
  let fakeTarPath: string;

  const OPENVEX_DOC = {
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

  const STUB_SCAN_RESULT: ScanResult = {
    target: { image: "nginx:latest" },
    identity: { type: "deb" },
    facts: [{ type: "imageId", data: "sha256:abc123" }],
  };

  const STUB_RESPONSE: PluginResponse = {
    scanResults: [STUB_SCAN_RESULT],
  };

  beforeAll(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "scan-vex-test-"));
    // Create a minimal fake tar file so getAndValidateArchivePath() passes.
    fakeTarPath = path.join(tmpDir, "image.tar");
    fs.writeFileSync(fakeTarPath, "fake tar content");
  });

  afterAll(() => {
    fs.rmSync(tmpDir, { recursive: true, force: true });
  });

  beforeEach(() => {
    (staticModule.analyzeStatically as jest.Mock).mockResolvedValue(
      STUB_RESPONSE,
    );
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it("attaches vexStatements fact to each scanResult when a valid VEX file is provided", async () => {
    const vexFilePath = path.join(tmpDir, "openvex.json");
    fs.writeFileSync(vexFilePath, JSON.stringify(OPENVEX_DOC), "utf8");

    const result = await scan({
      path: `docker-archive:${fakeTarPath}`,
      vexFilePath,
    });

    expect(result.scanResults).toHaveLength(1);
    const vexFact = result.scanResults[0].facts.find(
      (f) => f.type === "vexStatements",
    ) as VexStatementsFact | undefined;
    expect(vexFact).toBeDefined();
    expect(vexFact!.data.source).toBe(vexFilePath);
    expect(vexFact!.data.format).toBe("openvex");
    expect(vexFact!.data.statements).toHaveLength(1);
    expect(vexFact!.data.statements[0].vulnerabilityId).toBe("CVE-2024-0001");
  });

  it("adds pluginWarnings fact with error message when VEX file cannot be loaded", async () => {
    const nonExistentVexPath = path.join(tmpDir, "no-such-vex.json");

    const result = await scan({
      path: `docker-archive:${fakeTarPath}`,
      vexFilePath: nonExistentVexPath,
    });

    expect(result.scanResults).toHaveLength(1);
    // No vexStatements fact should be attached.
    expect(
      result.scanResults[0].facts.every((f) => f.type !== "vexStatements"),
    ).toBe(true);
    // A pluginWarnings fact should be present with the failure message.
    const warningsFact = result.scanResults[0].facts.find(
      (f) => f.type === "pluginWarnings",
    );
    expect(warningsFact).toBeDefined();
    const checks = (warningsFact!.data as any).parameterChecks as string[];
    expect(checks).toBeDefined();
    expect(
      checks.some((msg: string) => msg.includes("Failed to load VEX file")),
    ).toBe(true);
  });
});
