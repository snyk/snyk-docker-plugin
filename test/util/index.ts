import { join } from "path";

export function getFixture(fixturePath: string | string[]): string {
  if (typeof fixturePath === "string") {
    if (fixturePath.includes("/")) {
      fixturePath = fixturePath.split("/").filter(Boolean); // if it started or ended with /
    } else {
      fixturePath = [fixturePath];
    }
  }
  return join(__dirname, "..", "fixtures", ...fixturePath);
}
