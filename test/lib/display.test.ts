import { readFile } from "fs";
import { join } from "path";
import { test } from "tap";

import { DepGraphData } from "@snyk/dep-graph";
import { display } from "../../lib";
import { Options, ScanResult, TestResult } from "../../lib/types";

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

test("display", async (c) => {
  c.test("shows text mode when there is no issues", async (t) => {
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

    t.same(result, expectedDisplay, "the display is as expected");
  });

  c.test(
    "shows text mode when there is no issues and file option",
    async (t) => {
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

      t.same(result, expectedDisplay, "the display is as expected");
    },
  );

  c.test(
    "shows text mode when there is three issues from different severities",
    async (t) => {
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

      t.same(result, expectedDisplay, "the display is as expected");
    },
  );

  c.test("shows text mode when there is base image remediation", async (t) => {
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

    t.same(result, expectedDisplay, "the display is as expected");
  });
});
