const baseConfig = require("./jest.config");

module.exports = {
  ...baseConfig,
  testPathIgnorePatterns: [],
  testMatch: [
    "<rootDir>/lib/image-inspector.spec.ts",
    "<rootDir>/registry-scan.spec.ts",
  ],
};
