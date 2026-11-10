import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { resolveRegistryCredentials } from "../../../lib/extractor/registry-credentials";

function writeDockerConfig(dir: string, config: object): void {
  fs.writeFileSync(path.join(dir, "config.json"), JSON.stringify(config));
}

// Writes a fake `docker-credential-<name>` helper that answers `get` for one server URL.
function writeCredentialHelper(
  binDir: string,
  name: string,
  serverUrl: string,
  username: string,
  secret: string,
): void {
  const helperPath = path.join(binDir, `docker-credential-${name}`);
  const response = JSON.stringify({
    ServerURL: serverUrl,
    Username: username,
    Secret: secret,
  });
  fs.writeFileSync(
    helperPath,
    [
      "#!/bin/sh",
      "read -r server",
      `if [ "$1" = "get" ] && [ "$server" = "${serverUrl}" ]; then`,
      `  echo '${response}'`,
      "  exit 0",
      "fi",
      'echo "credentials not found in native keychain"',
      "exit 1",
    ].join("\n"),
  );
  fs.chmodSync(helperPath, 0o755);
}

const basicAuth = (username: string, password: string) =>
  Buffer.from(`${username}:${password}`).toString("base64");

describe("resolveRegistryCredentials", () => {
  const originalDockerConfig = process.env.DOCKER_CONFIG;
  const originalPath = process.env.PATH;
  let configDir: string;
  let binDir: string;

  beforeEach(() => {
    configDir = fs.mkdtempSync(path.join(os.tmpdir(), "docker-config-"));
    binDir = fs.mkdtempSync(path.join(os.tmpdir(), "docker-helpers-"));
    process.env.DOCKER_CONFIG = configDir;
    process.env.PATH = `${binDir}${path.delimiter}${originalPath}`;
  });

  afterEach(() => {
    fs.rmSync(configDir, { recursive: true, force: true });
    fs.rmSync(binDir, { recursive: true, force: true });
    if (originalDockerConfig === undefined) {
      delete process.env.DOCKER_CONFIG;
    } else {
      process.env.DOCKER_CONFIG = originalDockerConfig;
    }
    process.env.PATH = originalPath;
  });

  it("prefers explicitly provided credentials over docker config", async () => {
    writeDockerConfig(configDir, {
      auths: { "myregistry.io": { auth: basicAuth("docker", "config") } },
    });

    const creds = await resolveRegistryCredentials(
      "myregistry.io",
      "explicit-user",
      "explicit-pass",
    );

    expect(creds).toEqual({
      username: "explicit-user",
      password: "explicit-pass",
    });
  });

  it("returns no credentials when there is no docker config", async () => {
    expect(await resolveRegistryCredentials("myregistry.io")).toEqual({});
  });

  it("decodes base64 auths entries for the registry host", async () => {
    writeDockerConfig(configDir, {
      auths: { "https://myregistry.io": { auth: basicAuth("user", "p:ss") } },
    });

    expect(await resolveRegistryCredentials("myregistry.io")).toEqual({
      username: "user",
      password: "p:ss",
    });
  });

  it("maps Docker Hub registry hosts to the index.docker.io auths key", async () => {
    writeDockerConfig(configDir, {
      auths: {
        "https://index.docker.io/v1/": {
          auth: basicAuth("hubuser", "hubpass"),
        },
      },
    });

    expect(await resolveRegistryCredentials("registry-1.docker.io")).toEqual({
      username: "hubuser",
      password: "hubpass",
    });
  });

  it("does not return credentials for a different registry", async () => {
    writeDockerConfig(configDir, {
      auths: { "other.io": { auth: basicAuth("user", "pass") } },
    });

    expect(await resolveRegistryCredentials("myregistry.io")).toEqual({});
  });

  it("uses the credsStore helper", async () => {
    writeCredentialHelper(
      binDir,
      "teststore",
      "https://index.docker.io/v1/",
      "storeuser",
      "storesecret",
    );
    writeDockerConfig(configDir, {
      auths: { "https://index.docker.io/v1/": {} },
      credsStore: "teststore",
    });

    expect(await resolveRegistryCredentials("registry-1.docker.io")).toEqual({
      username: "storeuser",
      password: "storesecret",
    });
  });

  it("prefers a registry-specific credHelper over credsStore", async () => {
    const ecrHost = "123456789012.dkr.ecr.us-east-1.amazonaws.com";
    writeCredentialHelper(binDir, "testhelper", ecrHost, "AWS", "ecr-token");
    writeCredentialHelper(binDir, "teststore", ecrHost, "wrong", "wrong");
    writeDockerConfig(configDir, {
      credsStore: "teststore",
      credHelpers: { [ecrHost]: "testhelper" },
    });

    expect(await resolveRegistryCredentials(ecrHost)).toEqual({
      username: "AWS",
      password: "ecr-token",
    });
  });

  it("falls back to auths when the credsStore has no entry", async () => {
    writeCredentialHelper(binDir, "teststore", "other.io", "x", "y");
    writeDockerConfig(configDir, {
      credsStore: "teststore",
      auths: { "myregistry.io": { auth: basicAuth("user", "pass") } },
    });

    expect(await resolveRegistryCredentials("myregistry.io")).toEqual({
      username: "user",
      password: "pass",
    });
  });

  it("asks a Docker Hub credHelper for the canonical Hub address", async () => {
    writeCredentialHelper(
      binDir,
      "testhelper",
      "https://index.docker.io/v1/",
      "hubuser",
      "hubsecret",
    );
    writeDockerConfig(configDir, {
      credHelpers: { "docker.io": "testhelper" },
    });

    expect(await resolveRegistryCredentials("docker.io")).toEqual({
      username: "hubuser",
      password: "hubsecret",
    });
  });

  it("falls back to credsStore when the credHelper has no entry", async () => {
    writeCredentialHelper(binDir, "testhelper", "other.io", "x", "y");
    writeCredentialHelper(
      binDir,
      "teststore",
      "https://index.docker.io/v1/",
      "storeuser",
      "storesecret",
    );
    writeDockerConfig(configDir, {
      auths: { "https://index.docker.io/v1/": {} },
      credsStore: "teststore",
      credHelpers: { "registry-1.docker.io": "testhelper" },
    });

    expect(await resolveRegistryCredentials("docker.io")).toEqual({
      username: "storeuser",
      password: "storesecret",
    });
  });

  it("ignores identity tokens, which basic auth cannot use", async () => {
    writeCredentialHelper(
      binDir,
      "teststore",
      "myregistry.io",
      "<token>",
      "refresh-token",
    );
    writeDockerConfig(configDir, { credsStore: "teststore" });

    expect(await resolveRegistryCredentials("myregistry.io")).toEqual({});
  });

  it("does not execute helpers with unsafe names", async () => {
    writeDockerConfig(configDir, { credsStore: "../../bin/sh" });

    expect(await resolveRegistryCredentials("myregistry.io")).toEqual({});
  });

  it("returns no credentials when the config is not valid JSON", async () => {
    fs.writeFileSync(path.join(configDir, "config.json"), "{not json");

    expect(await resolveRegistryCredentials("myregistry.io")).toEqual({});
  });
});
