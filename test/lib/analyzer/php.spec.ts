import { phpFilesToScannedProjects } from "../../../lib/analyzer/applications";
import * as drupal10FilePathToContents from "../../fixtures/php/drupal10FilePathToContent.json";

describe("Can create dependency tree when some files are invalid", () => {
  it("Should succeed and return scan results", async () => {
    const scanResults = await phpFilesToScannedProjects(
      drupal10FilePathToContents,
    );
    expect(scanResults.length).toEqual(1);
  });
});
