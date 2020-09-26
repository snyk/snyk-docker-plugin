import { scan } from "../../../lib/index";

describe("handles bad input being provided", () => {
  it("should reject when provided with a non-existent image and tag", async () => {
    await expect(() =>
      scan({
        path: "not-here:latest",
      }),
    ).rejects.toEqual(Error("authentication required"));
  });
});
