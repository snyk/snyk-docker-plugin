import { execFile } from "child_process";
import * as Debug from "debug";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";

import { getErrorMessage } from "../error-utils";

const debug = Debug("snyk");

const DOCKER_HUB_HOST = "docker.io";
const DOCKER_HUB_ALIASES = [
  "docker.io",
  "index.docker.io",
  "registry-1.docker.io",
];
// The key Docker uses for Docker Hub in config.json and credential stores.
const DOCKER_HUB_SERVER_URL = "https://index.docker.io/v1/";
const CREDENTIAL_HELPER_TIMEOUT_MS = 10_000;
const CREDENTIAL_HELPER_NAME = /^[A-Za-z0-9._-]+$/;
// Credential helpers return this username for OAuth identity (refresh) tokens.
const IDENTITY_TOKEN_USERNAME = "<token>";

export interface RegistryCredentials {
  username?: string;
  password?: string;
}

interface DockerAuthEntry {
  auth?: string;
  username?: string;
  password?: string;
}

interface DockerConfig {
  auths?: Record<string, DockerAuthEntry>;
  credsStore?: string;
  credHelpers?: Record<string, string>;
}

/**
 * Resolves credentials for talking to a registry directly.
 * Explicit credentials (flags / SNYK_REGISTRY_* env vars) always win. Otherwise
 * we fall back to the credentials `docker login` stored, in Docker's own lookup
 * order: credHelpers[host], then credsStore, then auths[host].
 * Best-effort: never throws, and returns no credentials when none are found.
 */
export async function resolveRegistryCredentials(
  registryHost: string,
  username?: string,
  password?: string,
): Promise<RegistryCredentials> {
  if (username || password) {
    return { username, password };
  }

  try {
    const credentials = await getDockerConfigCredentials(registryHost);
    if (credentials) {
      debug(`using docker config credentials for registry ${registryHost}`);
      return credentials;
    }
  } catch (error) {
    debug(
      `could not read docker config credentials for ${registryHost}: ${getErrorMessage(
        error,
      )}`,
    );
  }
  return {};
}

async function getDockerConfigCredentials(
  registryHost: string,
): Promise<RegistryCredentials | undefined> {
  const config = readDockerConfig();
  if (!config) {
    return undefined;
  }

  const host = normalizeRegistryHost(registryHost);
  const findKey = (entries?: Record<string, unknown>) =>
    Object.keys(entries ?? {}).find(
      (key) => normalizeRegistryHost(key) === host,
    );

  const helperKey = findKey(config.credHelpers);
  if (helperKey) {
    return runCredentialHelper(config.credHelpers![helperKey], helperKey);
  }

  const authKey = findKey(config.auths);
  if (config.credsStore) {
    // Stores are keyed by the server address used at `docker login`, which
    // `auths` records (with an empty entry) when a store is in use.
    const serverUrl =
      authKey ?? (host === DOCKER_HUB_HOST ? DOCKER_HUB_SERVER_URL : host);
    const credentials = await runCredentialHelper(config.credsStore, serverUrl);
    if (credentials) {
      return credentials;
    }
  }

  return authKey ? decodeAuthEntry(config.auths![authKey]) : undefined;
}

function readDockerConfig(): DockerConfig | undefined {
  const configDir =
    process.env.DOCKER_CONFIG || path.join(os.homedir(), ".docker");
  const configPath = path.join(configDir, "config.json");
  if (!fs.existsSync(configPath)) {
    return undefined;
  }
  try {
    return JSON.parse(fs.readFileSync(configPath, "utf-8")) as DockerConfig;
  } catch (error) {
    debug(`invalid docker config at ${configPath}: ${getErrorMessage(error)}`);
    return undefined;
  }
}

// Reduces "https://index.docker.io/v1/", "registry-1.docker.io", etc. to a comparable host.
function normalizeRegistryHost(serverAddress: string): string {
  const host = serverAddress
    .replace(/^https?:\/\//, "")
    .split("/")[0]
    .toLowerCase();
  return DOCKER_HUB_ALIASES.includes(host) ? DOCKER_HUB_HOST : host;
}

function decodeAuthEntry(
  entry: DockerAuthEntry | undefined,
): RegistryCredentials | undefined {
  if (entry?.auth) {
    const decoded = Buffer.from(entry.auth, "base64").toString("utf-8");
    const separator = decoded.indexOf(":");
    if (separator > 0) {
      return {
        username: decoded.substring(0, separator),
        password: decoded.substring(separator + 1),
      };
    }
  }
  if (entry?.username && entry?.password) {
    return { username: entry.username, password: entry.password };
  }
  return undefined;
}

function runCredentialHelper(
  helperName: string,
  serverUrl: string,
): Promise<RegistryCredentials | undefined> {
  if (!CREDENTIAL_HELPER_NAME.test(helperName)) {
    debug(`ignoring docker credential helper with invalid name`);
    return Promise.resolve(undefined);
  }

  return new Promise((resolve) => {
    const child = execFile(
      `docker-credential-${helperName}`,
      ["get"],
      { timeout: CREDENTIAL_HELPER_TIMEOUT_MS, env: process.env },
      (error, stdout) => {
        if (error) {
          debug(
            `docker-credential-${helperName} returned no credentials for ${serverUrl}`,
          );
          return resolve(undefined);
        }
        try {
          const { Username, Secret } = JSON.parse(stdout);
          if (!Secret || Username === IDENTITY_TOKEN_USERNAME) {
            return resolve(undefined);
          }
          resolve({ username: Username, password: Secret });
        } catch {
          resolve(undefined);
        }
      },
    );
    child.stdin?.on("error", () => undefined);
    child.stdin?.end(serverUrl);
  });
}
