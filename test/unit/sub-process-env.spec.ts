import * as childProcess from "child_process";
import * as path from "path";
import { execute } from "../../lib/sub-process";

const PRINT_ENV = path.join(__dirname, "..", "fixtures", "print-env.js");

const TEST_ENV: Record<string, string> = {
  SNYK_TOKEN: "test-token",
  SNYK_OAUTH_TOKEN: "test-oauth-token",
  snyk_cfg_api: "test-cfg-api",
  HTTP_PROXY: "http://internal:1",
  SNYK_SYSTEM_HTTP_PROXY: "http://corp:3128",
  UNRELATED_VAR: "keep",
};
const isSnykKey = (key: string) => /^snyk_/i.test(key);
const hasPath = (keys: string[]) =>
  keys.some((key) => key.toUpperCase() === "PATH");

interface ChildEnv {
  keys: string[];
  HTTP_PROXY?: string;
  http_proxy?: string;
  UNRELATED_VAR?: string;
}

async function runPrintEnv(): Promise<ChildEnv> {
  const { stdout } = await execute(process.execPath, [PRINT_ENV]);
  return JSON.parse(stdout);
}

describe("child process environment", () => {
  let saved: Map<string, string | undefined>;

  beforeEach(() => {
    saved = new Map(
      Object.keys(TEST_ENV).map((key) => [key, process.env[key]]),
    );
    Object.assign(process.env, TEST_ENV);
  });

  afterEach(() => {
    jest.restoreAllMocks();
    for (const [key, value] of saved) {
      if (value === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = value;
      }
    }
  });

  it("passes spawn an env without SNYK_* variables and with the user proxy", async () => {
    const spy = jest.spyOn(childProcess, "spawn");
    await execute(process.execPath, [PRINT_ENV]);
    const env = spy.mock.calls[0][2]?.env;
    expect(env).toBeDefined();
    expect(Object.keys(env!).filter(isSnykKey)).toEqual([]);
    expect(env!.HTTP_PROXY).toBe("http://corp:3128");
    expect(env!.http_proxy).toBe("http://corp:3128");
    expect(env!.UNRELATED_VAR).toBe("keep");
    expect(hasPath(Object.keys(env!))).toBe(true);
  });

  it("the child process sees no SNYK_* variables and gets the user proxy", async () => {
    const child = await runPrintEnv();
    expect(child.keys.filter(isSnykKey)).toEqual([]);
    expect(child.HTTP_PROXY).toBe("http://corp:3128");
    expect(child.http_proxy).toBe("http://corp:3128");
    expect(child.UNRELATED_VAR).toBe("keep");
    expect(hasPath(child.keys)).toBe(true);
  });

  it("does not modify process.env", async () => {
    await execute(process.execPath, [PRINT_ENV]);
    expect(process.env.SNYK_TOKEN).toBe("test-token");
    expect(process.env.HTTP_PROXY).toBe("http://internal:1");
  });
});
