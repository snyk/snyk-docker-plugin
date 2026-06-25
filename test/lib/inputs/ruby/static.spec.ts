import { getRubyAppFileContentAction } from "../../../../lib/inputs/ruby/static";

describe("Ruby application file path matching", () => {
  const { filePathMatches } = getRubyAppFileContentAction;

  it("matches Gemfile and Gemfile.lock", () => {
    expect(filePathMatches("/app/Gemfile")).toBe(true);
    expect(filePathMatches("/app/Gemfile.lock")).toBe(true);
  });

  it("matches deleted Gemfile and Gemfile.lock whiteouts", () => {
    expect(filePathMatches("/app/.wh.Gemfile")).toBe(true);
    expect(filePathMatches("/app/.wh.Gemfile.lock")).toBe(true);
  });

  it("does not match unrelated Ruby files", () => {
    expect(filePathMatches("/app/config.ru")).toBe(false);
    expect(filePathMatches("/app/app.rb")).toBe(false);
    expect(filePathMatches("/app/gems.locked")).toBe(false);
  });
});
