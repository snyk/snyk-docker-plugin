import { readFile } from "fs";
import { join } from "path";

import { DepGraphData } from "@snyk/dep-graph";
import { display } from "../../lib";
import { Options, ScanResult, TestResult } from "../../lib/types";

describe("display", () => {
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
