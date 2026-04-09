import { readFile } from "fs";
import { join } from "path";

import { DepGraphData } from "@snyk/dep-graph";
import { Options, ScanResult, TestResult } from "../../lib/types";

describe("display", () => {
  let display: typeof import("../../lib").display;

  beforeAll(() => {
    // Fixture files include chalk ANSI sequences; load `display` after env is set so chalk enables color.
    process.env.FORCE_COLOR = "1";
    delete process.env.NO_COLOR;
    display = require("../../lib").display;
  });

  test("shows text mode when there is no issues", async () => {
    const expectedDisplay = await readFixture(
      "display/output",
      "no-issues.txt",
    );
    const debDepGraphData: DepGraphData = JSON.parse(
      await readFixture("display", "deb-dep-graph.json"),
    );
    const rpmImageScanResult: ScanResult = JSON.parse(
      await readFixture("display/scan-results", "rpm.json"),
    );
    const scanResults: ScanResult[] = [rpmImageScanResult];
    const testResults: TestResult[] = [
      {
        org: "org-test",
        licensesPolicy: null,
        docker: {},
        issues: [],
        issuesData: {},
        depGraphData: debDepGraphData,
      },
    ];
    const errors: string[] = [];
    const options: Options = {
      path: "snyk/kubernetes-monitor",
      config: {},
    } as Options;

    const result = await display(scanResults, testResults, errors, options);

    //  the display is as expected
    expect(result).toEqual(expectedDisplay);
  });

  test("shows text mode when there is no issues and file option", async () => {
    const expectedDisplay = await readFixture(
      "display/output",
      "no-issues-with-file-options.txt",
    );
    const debDepGraphData: DepGraphData = JSON.parse(
      await readFixture("display", "deb-dep-graph.json"),
    );
    const rpmImageScanResult: ScanResult = JSON.parse(
      await readFixture("display/scan-results", "rpm.json"),
    );
    const scanResults: ScanResult[] = [rpmImageScanResult];
    const testResults: TestResult[] = [
      {
        org: "org-test",
        licensesPolicy: null,
        docker: {},
        issues: [],
        issuesData: {},
        depGraphData: debDepGraphData,
      },
    ];
    const errors: string[] = [];
    const options: Options = {
      config: {},
      file: "Dockerfile",
    } as Options;

    const result = await display(scanResults, testResults, errors, options);

    //  the display is as expected
    expect(result).toEqual(expectedDisplay);
  });

  test("shows text mode when there is three issues from different severities", async () => {
    const expectedDisplay = await readFixture(
      "display/output",
      "a-few-issues.txt",
    );
    const debDepGraphData: DepGraphData = JSON.parse(
      await readFixture("display", "deb-dep-graph.json"),
    );
    const rpmImageScanResult: ScanResult = JSON.parse(
      await readFixture("display/scan-results", "rpm.json"),
    );
    const testResultWithIssues: TestResult = JSON.parse(
      await readFixture("display/test-results", "with-few-issues.txt"),
    );
    testResultWithIssues.depGraphData = debDepGraphData;
    const scanResults: ScanResult[] = [rpmImageScanResult];
    const testResults: TestResult[] = [testResultWithIssues];
    const errors: string[] = [];
    const options: Options = {
      path: "ubuntu",
      config: {
        disableSuggestions: "true",
      },
    };

    const result = await display(scanResults, testResults, errors, options);

    //  the display is as expected
    expect(result).toEqual(expectedDisplay);
  });

  test("shows text mode when there is base image remediation", async () => {
    const expectedDisplay = await readFixture(
      "display/output",
      "only-base-image-remediations.txt",
    );
    const debDepGraphData: DepGraphData = JSON.parse(
      await readFixture("display", "deb-dep-graph.json"),
    );
    const rpmImageScanResult: ScanResult = JSON.parse(
      await readFixture("display/scan-results", "rpm.json"),
    );
    const testResultWithIssues: TestResult = JSON.parse(
      await readFixture(
        "display/test-results",
        "only-base-image-remediation.txt",
      ),
    );
    testResultWithIssues.depGraphData = debDepGraphData;
    const scanResults: ScanResult[] = [rpmImageScanResult];
    const testResults: TestResult[] = [testResultWithIssues];
    const errors: string[] = [];
    const options: Options = {
      path: "ubuntu",
      isDockerUser: true,
      config: {
        disableSuggestions: "true",
      },
    };

    const result = await display(scanResults, testResults, errors, options);

    //  the display is as expected
    expect(result).toEqual(expectedDisplay);
  });

  describe("image digest metadata", () => {
    test("includes full digest when imageId fact is at most 24 characters", async () => {
      const debDepGraphData: DepGraphData = JSON.parse(
        await readFixture("display", "deb-dep-graph.json"),
      );
      const rpmImageScanResult: ScanResult = JSON.parse(
        await readFixture("display/scan-results", "rpm.json"),
      );
      const shortDigest = "sha256:abc123456789012"; // 22 chars
      rpmImageScanResult.facts.push({
        type: "imageId",
        data: shortDigest,
      });
      const scanResults: ScanResult[] = [rpmImageScanResult];
      const testResults: TestResult[] = [
        {
          org: "org-test",
          licensesPolicy: null,
          docker: {},
          issues: [],
          issuesData: {},
          depGraphData: debDepGraphData,
        },
      ];
      const errors: string[] = [];
      const options: Options = {
        path: "snyk/kubernetes-monitor",
        config: { disableSuggestions: "true" },
      } as Options;

      const result = await display(scanResults, testResults, errors, options);

      expect(result).toContain(shortDigest);
      expect(result).toContain("Image digest:");
    });

    test("truncates digest to first 15 and last 8 characters when longer than 24", async () => {
      const debDepGraphData: DepGraphData = JSON.parse(
        await readFixture("display", "deb-dep-graph.json"),
      );
      const rpmImageScanResult: ScanResult = JSON.parse(
        await readFixture("display/scan-results", "rpm.json"),
      );
      const longDigest =
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
      rpmImageScanResult.facts.push({
        type: "imageId",
        data: longDigest,
      });
      const scanResults: ScanResult[] = [rpmImageScanResult];
      const testResults: TestResult[] = [
        {
          org: "org-test",
          licensesPolicy: null,
          docker: {},
          issues: [],
          issuesData: {},
          depGraphData: debDepGraphData,
        },
      ];
      const errors: string[] = [];
      const options: Options = {
        path: "snyk/kubernetes-monitor",
        config: { disableSuggestions: "true" },
      } as Options;

      const result = await display(scanResults, testResults, errors, options);

      expect(result).toContain("sha256:01234567...89abcdef");
      expect(result).not.toContain(longDigest);
    });

    test("omits image digest line when imageId fact has no data", async () => {
      const debDepGraphData: DepGraphData = JSON.parse(
        await readFixture("display", "deb-dep-graph.json"),
      );
      const rpmImageScanResult: ScanResult = JSON.parse(
        await readFixture("display/scan-results", "rpm.json"),
      );
      rpmImageScanResult.facts.push({
        type: "imageId",
        data: "",
      });
      const scanResults: ScanResult[] = [rpmImageScanResult];
      const testResults: TestResult[] = [
        {
          org: "org-test",
          licensesPolicy: null,
          docker: {},
          issues: [],
          issuesData: {},
          depGraphData: debDepGraphData,
        },
      ];
      const errors: string[] = [];
      const options: Options = {
        path: "snyk/kubernetes-monitor",
        config: { disableSuggestions: "true" },
      } as Options;

      const result = await display(scanResults, testResults, errors, options);

      expect(result).not.toContain("Image digest:");
    });
  });

  function readFixture(fixture: string, filename: string): Promise<string> {
    const dir = join("./", "test", "fixtures", fixture);
    const file = join(dir, filename);
    return new Promise((resolve, reject) => {
      readFile(file, "utf-8", (err, data) => {
        if (err) {
          reject(err);
        }
        resolve(data);
      });
    });
  }
});
