const shared = {
  preset: "ts-jest",
  setupFilesAfterEnv: [
    "<rootDir>/test/jest-snapshot-strip-analytics.cjs",
    "<rootDir>/test/matchers/setup.ts",
  ],
  testEnvironment: "node",
  // TODO: This is here until a bug in Jest (which in turn affects ts-jest) is resolved.
  // It affects our CI/CD runs and makes the machine run out of memory.
  // https://github.com/facebook/jest/issues/10550
  // https://snyk.slack.com/archives/CLW30N31V/p1602232569018000?thread_ts=1602230753.017500&cid=CLW30N31V
  transform: {
    "^.+\\.tsx?$": [
      "ts-jest",
      {
        isolatedModules: true,
      },
    ],
  },
};

module.exports = {
  testTimeout: 600000, // 10 minutes
  // Use 3 of 4 CircleCI cores
  // https://github.com/jestjs/jest/issues/11956#issuecomment-1212925677
  maxWorkers: 3,
  reporters: [
    "default",
    ["jest-junit", { outputDirectory: "test/reports", addFileAttribute: true }],
  ],
  projects: [
    {
      ...shared,
      displayName: "unit",
      testMatch: ["<rootDir>/test/(lib|unit)/**/*.spec.ts"],
    },
    {
      ...shared,
      displayName: "system",
      testMatch: ["<rootDir>/test/system/**/*.spec.ts"],
    },
    {
      ...shared,
      displayName: "windows",
      testMatch: ["<rootDir>/test/windows/**/*.spec.ts"],
      testPathIgnorePatterns: [
        "<rootDir>/test/windows/lib/image-inspector.spec.ts",
        "<rootDir>/test/windows/registry-scan.spec.ts",
      ],
    },
    {
      ...shared,
      displayName: "windows-docker",
      testMatch: [
        "<rootDir>/test/windows/lib/image-inspector.spec.ts",
        "<rootDir>/test/windows/registry-scan.spec.ts",
      ],
    },
  ],
};
