import { DepGraphData } from "@snyk/dep-graph";
import { display } from "../../lib";
import {
  BaseImageLifecycle,
  BaseImageLifecycleStatus,
  Options,
  ScanResult,
  TestResult,
} from "../../lib/types";
import { facts } from "../../lib";

/**
 * Minimal ScanResult fixture for display tests.
 */
const minimalScanResult: ScanResult = {
  target: { image: "docker-image|ubuntu:18.04" },
  identity: { type: "deb", args: { platform: "linux/amd64" } },
  facts: [],
};

/**
 * Minimal DepGraphData that satisfies the display() call without real data.
 */
const emptyDepGraphData: DepGraphData = {
  schemaVersion: "1.2.0",
  pkgManager: { name: "deb" },
  pkgs: [{ id: "ubuntu:18.04@1.0", info: { name: "ubuntu:18.04", version: "1.0" } }],
  graph: {
    rootNodeId: "root-node",
    nodes: [{ nodeId: "root-node", pkgId: "ubuntu:18.04@1.0", deps: [] }],
  },
};

const baseOptions: Options = {
  path: "ubuntu:18.04",
  config: { disableSuggestions: "true" },
  isDockerUser: false,
};

function makeTestResult(dockerOverrides?: Partial<TestResult["docker"]>): TestResult {
  return {
    org: "test-org",
    licensesPolicy: null,
    docker: {
      baseImage: "ubuntu:18.04",
      ...dockerOverrides,
    },
    issues: [],
    issuesData: {},
    depGraphData: emptyDepGraphData,
  };
}

describe("Base image lifecycle EOL display", () => {
  describe("when baseImageLifecycle is not present", () => {
    it("should not show an EOL line in the output", async () => {
      const testResult = makeTestResult();
      const output = await display([minimalScanResult], [testResult], [], baseOptions);
      expect(output).not.toContain("Base image EOL:");
      expect(output).not.toContain("End-of-Life");
    });
  });

  describe("when baseImageLifecycle.isEol is false", () => {
    it("should not show an EOL line in the output", async () => {
      const lifecycle: BaseImageLifecycle = {
        isEol: false,
        lifecycleStatus: "supported",
      };
      const testResult = makeTestResult({ baseImageLifecycle: lifecycle });
      const output = await display([minimalScanResult], [testResult], [], baseOptions);
      expect(output).not.toContain("Base image EOL:");
      expect(output).not.toContain("End-of-Life");
    });
  });

  describe("when baseImageLifecycle.isEol is true (without eolDate)", () => {
    it("should show an EOL warning in the metadata section", async () => {
      const lifecycle: BaseImageLifecycle = {
        isEol: true,
        lifecycleStatus: "eol",
      };
      const testResult = makeTestResult({ baseImageLifecycle: lifecycle });
      const output = await display([minimalScanResult], [testResult], [], baseOptions);
      expect(output).toContain("Base image EOL:");
      expect(output).toContain("End-of-Life");
      expect(output).not.toContain("reached End-of-Life on");
    });
  });

  describe("when baseImageLifecycle.isEol is true with a known eolDate", () => {
    it("should show the EOL date in the metadata section", async () => {
      const lifecycle: BaseImageLifecycle = {
        isEol: true,
        lifecycleStatus: "eol",
        eolDate: "2023-04-30",
      };
      const testResult = makeTestResult({ baseImageLifecycle: lifecycle });
      const output = await display([minimalScanResult], [testResult], [], baseOptions);
      expect(output).toContain("Base image EOL:");
      expect(output).toContain("reached End-of-Life on 2023-04-30");
    });
  });

  describe("when lifecycleStatus is 'unknown' and isEol is false", () => {
    it("should not show an EOL line in the output", async () => {
      const lifecycle: BaseImageLifecycle = {
        isEol: false,
        lifecycleStatus: "unknown",
      };
      const testResult = makeTestResult({ baseImageLifecycle: lifecycle });
      const output = await display([minimalScanResult], [testResult], [], baseOptions);
      expect(output).not.toContain("Base image EOL:");
    });
  });
});

describe("BaseImageLifecycle types", () => {
  it("accepts all valid lifecycle status values", () => {
    const supportedStatuses: BaseImageLifecycleStatus[] = [
      "supported",
      "eol",
      "unknown",
    ];
    for (const status of supportedStatuses) {
      const lifecycle: BaseImageLifecycle = {
        isEol: status === "eol",
        lifecycleStatus: status,
      };
      expect(lifecycle.lifecycleStatus).toBe(status);
    }
  });

  it("allows optional eolDate field", () => {
    const withDate: BaseImageLifecycle = {
      isEol: true,
      lifecycleStatus: "eol",
      eolDate: "2024-04-30",
    };
    const withoutDate: BaseImageLifecycle = {
      isEol: true,
      lifecycleStatus: "eol",
    };
    expect(withDate.eolDate).toBe("2024-04-30");
    expect(withoutDate.eolDate).toBeUndefined();
  });
});

describe("BaseImageLifecycleFact", () => {
  it("can be constructed with all fields", () => {
    const fact: facts.BaseImageLifecycleFact = {
      type: "baseImageLifecycle",
      data: {
        isEol: true,
        lifecycleStatus: "eol",
        eolDate: "2023-04-30",
      },
    };
    expect(fact.type).toBe("baseImageLifecycle");
    expect(fact.data.isEol).toBe(true);
    expect(fact.data.lifecycleStatus).toBe("eol");
    expect(fact.data.eolDate).toBe("2023-04-30");
  });

  it("can be constructed without optional eolDate", () => {
    const fact: facts.BaseImageLifecycleFact = {
      type: "baseImageLifecycle",
      data: {
        isEol: false,
        lifecycleStatus: "supported",
      },
    };
    expect(fact.type).toBe("baseImageLifecycle");
    expect(fact.data.isEol).toBe(false);
    expect(fact.data.lifecycleStatus).toBe("supported");
    expect(fact.data.eolDate).toBeUndefined();
  });
});
