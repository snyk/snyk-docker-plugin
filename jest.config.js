module.exports = {
  preset: "ts-jest",
  setupFilesAfterEnv: [
    "<rootDir>/test/jest-snapshot-strip-analytics.cjs",
    "<rootDir>/test/matchers/setup.ts",
  ],
  testEnvironment: "node",
  testMatch: ["<rootDir>/test/**/*.spec.ts"],
  testPathIgnorePatterns: ["<rootDir>/test/windows/"],
  testTimeout: 600000, // 10 minutes
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
  // Use 3 of 4 CircleCI cores
  // https://github.com/jestjs/jest/issues/11956#issuecomment-1212925677
  maxWorkers: 3,
  reporters: ["default", ["jest-junit", { outputDirectory: "test/reports" }]],
};
