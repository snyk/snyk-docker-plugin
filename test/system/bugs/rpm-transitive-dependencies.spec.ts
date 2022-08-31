import { scan } from "../../../lib";
import { DockerFileAnalysis } from "../../../lib/dockerfile";
import { getFixture } from "../../util";

/**
 * The following bug proves that RPM packages do not have transitive dependencies.
 * This is a limitation in our RPM scanning currently, where we cannot produce a tree of dependencies.
 * More context here: https://snyk.slack.com/archives/CDSMEJ29E/p1592473698145800
 */
describe("BUG: Dockerfile analysis does not produce transitive dependencies for RPM projects", () => {
  it("should not produce transitive dependencies", async () => {
    const dockerfilePath = getFixture("dockerfiles/bug/Dockerfile");
    const fixturePath = getFixture("docker-archives/docker-save/bug.tar.gz");
    const imagePath = `docker-archive:${fixturePath}`;

    const pluginResult = await scan({
      path: imagePath,
      file: dockerfilePath,
    });

    expect(pluginResult).toMatchSnapshot();

    const dockerfileAnalysis: DockerFileAnalysis =
      pluginResult.scanResults[0].facts.find(
        (fact) => fact.type === "dockerfileAnalysis",
      )!.data;
    // "BUG: transitive dependency 'kernel-headers' not in 'dockerfilePackages'"
    expect(Object.keys(dockerfileAnalysis.dockerfilePackages)).not.toContain(
      "kernel-headers",
    );
  });
});
