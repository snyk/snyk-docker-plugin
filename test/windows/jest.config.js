const path = require("path");

// In Bazel, JS_BINARY__RUNFILES points to the runfiles tree root.
// Outside Bazel (plain `jest` invocation), resolve two levels up from this
// config file (test/windows/ -> test/ -> repo root).
const rootDir = process.env.JS_BINARY__RUNFILES
  ? path.join(process.env.JS_BINARY__RUNFILES, process.env.JS_BINARY__WORKSPACE || "_main")
  : path.resolve(__dirname, "../..");

module.exports = {
  rootDir,
  setupFilesAfterEnv: ["<rootDir>/test/matchers/setup.ts"],
  testEnvironment: "node",
  testMatch: ["<rootDir>/test/windows/**/*.spec.ts"],
  testTimeout: 600000,
  // TODO: This option is printing Array\Object prefixing arrays\objects in snapshots files
  // this settings were added when migrated to Jest 29 to support the old snapshots format
  // this settings should be removed in the future after snapshot migration to the new Jest snapshot format
  // more details over the breaking change of Jest snapshot format can be found here:
  // https://jestjs.io/docs/next/upgrading-to-jest29#snapshot-format
  snapshotFormat: {
    escapeString: true,
    printBasicPrototype: true,
  },

  // TODO: This is here until a bug in Jest (which in turn affects ts-jest) is resolved.
  // It affects our CI/CD runs and makes the machine run out of memory.
  // https://github.com/facebook/jest/issues/10550
  // https://snyk.slack.com/archives/CLW30N31V/p1602232569058000?thread_ts=1602230753.017500&cid=CLW30N31V
  transform: {
    '^.+\\.tsx?$': [
      'ts-jest', {
        isolatedModules: true
      },
    ],
  },
};
