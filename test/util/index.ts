import { readFileSync } from "fs";
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

export function getObjFromFixture(fixturePath) {
  const text = getTextFromFixture(fixturePath);
  return JSON.parse(text);
}

export function getTextFromFixture(fixturePath) {
  const path = getFixture(fixturePath);
  return readFileSync(path, { encoding: "utf-8" });
}
