import * as path from "path";
import { execute } from "../../lib/sub-process";

const CHILD_ENV_FIXTURE = path.join(
  __dirname,
  "..",
  "fixtures",
  "sub-process",
  "print-env.js",
);

// Sets process.env keys for one test and returns a restore function.
// Keys that were absent are deleted on restore, never assigned undefined.
function setProcessEnv(vars: Record<string, string>): () => void {
  const saved = new Map<string, string | undefined>();
  for (const [key, value] of Object.entries(vars)) {
    saved.set(key, process.env[key]);
    process.env[key] = value;
  }
  return () => {
    for (const [key, value] of saved) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  };
}

async function runChildEnv(): Promise<Record<string, string>> {
  const { stdout } = await execute("node", [CHILD_ENV_FIXTURE]);
  return JSON.parse(stdout);
}

describe("sub-process child environment", () => {
  const inheritedVars = {
    SNYK_TOKEN: "secret-token",
    SNYK_OAUTH_TOKEN: "secret-oauth-token",
    snyk_cfg_api: "secret-cfg-api",
    SNYK_REGISTRY_USERNAME: "registry-user",
    SNYK_REGISTRY_PASSWORD: "secret-registry-password",
    HTTP_PROXY: "http://internal:1",
    SNYK_SYSTEM_HTTP_PROXY: "http://corp:3128",
    UNRELATED_VAR: "keep",
  };

  let restore: () => void;

  beforeEach(() => {
    restore = setProcessEnv(inheritedVars);
  });

  afterEach(() => {
    restore();
  });

  it("does not pass SNYK_* variables to the child process", async () => {
    const childEnv = await runChildEnv();

    const leaked = Object.keys(childEnv).filter((key) => /^snyk_/i.test(key));
    expect(leaked).toEqual([]);
  });

  it("restores the system proxy and keeps unrelated variables", async () => {
    const childEnv = await runChildEnv();

    expect(childEnv.HTTP_PROXY).toBe("http://corp:3128");
    expect(childEnv.http_proxy).toBe("http://corp:3128");
    expect(childEnv.UNRELATED_VAR).toBe("keep");
    expect(
      Object.keys(childEnv).some((key) => key.toUpperCase() === "PATH"),
    ).toBe(true);
  });
});
