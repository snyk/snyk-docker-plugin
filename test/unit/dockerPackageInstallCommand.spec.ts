import { toBeDockerPackageInstallCommand } from "../matchers/dockerPackageInstallCommand";

// Test all of the combinations of package install commands for the regex in test/matchers/dockerPackageInstallCommand.ts:11
describe("valid package install commands", () => {
  const testCases = [
    { command: "rpm -i nginx", pkg: "nginx" },
    { command: "rpm --install nginx", pkg: "nginx" },
    { command: "apk add curl", pkg: "curl" },
    { command: "apk --update add curl", pkg: "curl" },
    { command: "apk -u add curl", pkg: "curl" },
    { command: "apk --no-cache add curl", pkg: "curl" },
    { command: "apt-get install curl", pkg: "curl" },
    { command: "apt-get --yes install curl", pkg: "curl" },
    { command: "apt-get -y install curl", pkg: "curl" },
    { command: "apt install curl", pkg: "curl" },
    { command: "yum install curl", pkg: "curl" },
    { command: "aptitude install curl", pkg: "curl" },
  ];

  testCases.forEach(({ command, pkg }) => {
    it(`recognizes "${command}" as valid`, () => {
      const result = toBeDockerPackageInstallCommand(command, pkg);
      expect(result.pass).toBe(true);

      // Verify success message
      expect(result.message()).toContain("not to be a package installCommand");
    });
  });
});

describe("invalid package install commands", () => {
  const testCases = [
    {
      command: "not a command",
      pkg: "curl",
      reason: "not a package manager command",
    },
    {
      command: "apt-get install vim",
      pkg: "curl",
      reason: "wrong package name",
    },
    {
      command: "RUN apt-get install curl",
      pkg: "curl",
      reason: "prefixed with RUN",
    },
    {
      command: "RUN /bin/sh -c apt-get install curl",
      pkg: "curl",
      reason: "RUN with shell",
    },
  ];

  testCases.forEach(({ command, pkg, reason }) => {
    it(`rejects "${command}" - ${reason}`, () => {
      const result = toBeDockerPackageInstallCommand(command, pkg);
      expect(result.pass).toBe(false);

      // Verify failure message
      expect(result.message()).toContain("to be a package installCommand");
    });
  });
});
