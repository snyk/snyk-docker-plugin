import { PackageInfo } from "@snyk/rpm-parser/lib/rpm/types";
import { mapRpmSqlitePackages } from "../../../../lib/analyzer/package-managers/rpm";

describe("Correctly maps RPM package version", () => {
  it("formats version without epoch", () => {
    const mappedResults = mapRpmSqlitePackages("image", [
      {
        name: "pkg1",
        version: "1.2.3",
        release: "1",
        size: 1,
      },
    ]);

    const expected = [
      {
        Name: "pkg1",
        Version: "1.2.3-1",
        Source: undefined,
        Provides: [],
        Deps: {},
        AutoInstalled: undefined,
      },
    ];
    expect(mappedResults.Analysis).toMatchObject(expected);
  });
  it("formats version with epoch == 0", () => {
    const mappedResults = mapRpmSqlitePackages("image", [
      {
        name: "pkg2",
        version: "1.2.3",
        release: "2",
        epoch: 0,
        size: 1,
      },
    ]);

    const expected = [
      {
        Name: "pkg2",
        Version: "1.2.3-2",
        Source: undefined,
        Provides: [],
        Deps: {},
        AutoInstalled: undefined,
      },
    ];
    expect(mappedResults.Analysis).toMatchObject(expected);
  });
  it("formats version with epoch", () => {
    const mappedResults = mapRpmSqlitePackages("image", [
      {
        name: "pkg3",
        version: "1.2.3",
        release: "3",
        epoch: 1,
        size: 1,
      },
    ]);

    const expected = [
      {
        Name: "pkg3",
        Version: "1:1.2.3-3",
        Source: undefined,
        Provides: [],
        Deps: {},
        AutoInstalled: undefined,
      },
    ];
    expect(mappedResults.Analysis).toMatchObject(expected);
  });
});
