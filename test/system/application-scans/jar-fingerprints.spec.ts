import { scan } from "../../../lib";
import { execute } from "../../../lib/sub-process";

describe("jar fingerprint scanning", () => {
  afterAll(async () => {
    await execute("docker", [
      "image",
      "rm",
      "atlassian/bitbucket-server@sha256:83fd0265da3ea6c8d0ccf6edfc9bc348f08fecfa105c7e6d4356751bd57d462b",
    ]).catch();
  });

  it.concurrent("should correctly detect dependencies", async () => {
    const result = await scan({
      path:
        "atlassian/bitbucket-server@sha256:83fd0265da3ea6c8d0ccf6edfc9bc348f08fecfa105c7e6d4356751bd57d462b",
      "app-vulns": true,
    });
    expect(result).toMatchSnapshot();
  });
});
