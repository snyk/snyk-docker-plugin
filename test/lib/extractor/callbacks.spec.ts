import { PassThrough, Readable } from "stream";
import {
  applyCallbacks,
  isResultEmpty,
} from "../../../lib/extractor/callbacks";
import { ExtractAction } from "../../../lib/extractor/types";

describe("callbacks", () => {
  describe("applyCallbacks", () => {
    it("should handle actions with callbacks", async () => {
      const testContent = "test file content";
      const inputStream = Readable.from([testContent]);

      const actions: ExtractAction[] = [
        {
          actionName: "test-action",
          filePathMatches: (filePath: string) => true,
          callback: async (stream: Readable) => {
            const chunks: Buffer[] = [];
            for await (const chunk of stream) {
              chunks.push(Buffer.from(chunk));
            }
            return Buffer.concat(chunks).toString();
          },
        },
      ];

      const result = await applyCallbacks(actions, inputStream);

      expect(result["test-action"]).toBe(testContent);
    });

    it("should handle actions without callbacks (default to streamToString)", async () => {
      // Test the missing branch where action.callback is undefined
      const testContent = "test file content without callback";
      const inputStream = Readable.from([testContent]);

      const actions: ExtractAction[] = [
        {
          actionName: "no-callback-action",
          filePathMatches: (filePath: string) => true,
          // callback is intentionally undefined to test the default behavior
        },
      ];

      const result = await applyCallbacks(actions, inputStream);

      expect(result["no-callback-action"]).toBe(testContent);
    });

    it("should handle multiple actions on the same stream", async () => {
      const testContent = "shared content";
      const inputStream = Readable.from([testContent]);

      const actions: ExtractAction[] = [
        {
          actionName: "action1",
          filePathMatches: (filePath: string) => true,
          callback: async (stream: Readable) => {
            const chunks: Buffer[] = [];
            for await (const chunk of stream) {
              chunks.push(Buffer.from(chunk));
            }
            return Buffer.concat(chunks).toString().toUpperCase();
          },
        },
        {
          actionName: "action2",
          filePathMatches: (filePath: string) => true,
          // No callback - should use default
        },
      ];

      const result = await applyCallbacks(actions, inputStream);

      expect(result.action1).toBe("SHARED CONTENT");
      expect(result.action2).toBe(testContent);
    });

    it("should handle callbacks that return null/undefined", async () => {
      const testContent = "test content";
      const inputStream = Readable.from([testContent]);

      const actions: ExtractAction[] = [
        {
          actionName: "null-action",
          filePathMatches: (filePath: string) => true,
          callback: async (stream: Readable) => {
            // Consume the stream but return null
            for await (const chunk of stream) {
              // Do nothing
            }
            return null;
          },
        },
        {
          actionName: "undefined-action",
          filePathMatches: (filePath: string) => true,
          callback: async (stream: Readable) => {
            // Consume the stream but return undefined
            for await (const chunk of stream) {
              // Do nothing
            }
            return undefined;
          },
        },
      ];

      const result = await applyCallbacks(actions, inputStream);

      // When content is null/undefined, it shouldn't be added to result
      expect(result["null-action"]).toBeUndefined();
      expect(result["undefined-action"]).toBeUndefined();
      expect(Object.keys(result)).toHaveLength(0);
    });

    it("should pass streamSize parameter to callbacks", async () => {
      const testContent = "sized content";
      const inputStream = Readable.from([testContent]);
      const streamSize = 12345;
      let receivedSize: number | undefined;

      const actions: ExtractAction[] = [
        {
          actionName: "size-aware-action",
          filePathMatches: (filePath: string) => true,
          callback: async (stream: Readable, size?: number) => {
            receivedSize = size;
            const chunks: Buffer[] = [];
            for await (const chunk of stream) {
              chunks.push(Buffer.from(chunk));
            }
            return Buffer.concat(chunks).toString();
          },
        },
      ];

      await applyCallbacks(actions, inputStream, streamSize);

      expect(receivedSize).toBe(streamSize);
    });
  });

  describe("isResultEmpty", () => {
    it("should return true for empty result", () => {
      expect(isResultEmpty({})).toBe(true);
    });

    it("should return false for non-empty result", () => {
      expect(isResultEmpty({ "some-action": "some-content" })).toBe(false);
    });
  });
});
