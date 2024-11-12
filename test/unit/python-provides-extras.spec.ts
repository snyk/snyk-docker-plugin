import { findProvidesExtras } from "../../lib/python-parser/provides-extra";
import { getTextFromFixture } from "../util";

describe("findProvidesExtras", () => {
  it("finds single extra name", () => {
    const text = getTextFromFixture(
      "python/ok/site-packages/Jinja2-3.1.2.dist-info/METADATA",
    );
    const lines = text.split("\n");
    const received = findProvidesExtras(lines);
    expect(received).toEqual(["i18n"]);
  });

  it("finds multiple extra names", () => {
    const text = getTextFromFixture(
      "python/ok/site-packages/rpc.py-0.4.2.dist-info/METADATA",
    );
    const lines = text.split("\n");
    const received = findProvidesExtras(lines);
    expect(received).toEqual(["client", "full", "msgpack", "type"]);
  });

  it("would remove duplicates if found", () => {
    const text =
      "Provides-Extra: one\nProvides-Extra: two\nProvides-Extra: one\nProvides-Extra: three\n";
    const lines = text.split("\n");
    const received = findProvidesExtras(lines);
    expect(received).toEqual(["one", "two", "three"]); // removes duplicate 'one'
  });
});
