import * as fs from "fs";
import * as path from "path";
import { parseFile } from "../../lib/analyzer/package-managers/apk";

const fixturePath = path.join(
  __dirname,
  "../fixtures/os/alpine_3_7_0/fs/lib/apk/db/installed",
);

describe("apk installed-db file list parsing", () => {
  it("parses F:/R: file paths for packages", () => {
    const content = fs.readFileSync(fixturePath, "utf8");
    const packages = parseFile(content);

    const busybox = packages.find((pkg) => pkg.Name === "busybox");
    expect(busybox).toBeDefined();
    expect(busybox!.Files).toEqual(
      expect.arrayContaining(["/bin/busybox", "/bin/sh", "/etc/securetty"]),
    );
    expect(busybox!.Directories).toEqual(
      expect.arrayContaining(["/bin", "/etc", "/sbin"]),
    );

    const musl = packages.find((pkg) => pkg.Name === "musl");
    expect(musl).toBeDefined();
    expect(musl!.Files).toEqual(
      expect.arrayContaining([
        "/lib/libc.musl-x86_64.so.1",
        "/lib/ld-musl-x86_64.so.1",
      ]),
    );
  });
});
