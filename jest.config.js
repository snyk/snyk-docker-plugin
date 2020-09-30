module.exports = {
  preset: "ts-jest",
  testEnvironment: "node",
  testMatch: ["<rootDir>/test/**/*.spec.ts", "!<rootDir>/test/windows/**"],
  testTimeout: 600000, // 10 minutes
};
