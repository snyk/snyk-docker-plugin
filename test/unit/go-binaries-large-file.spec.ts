import { Readable } from "stream";
import { getGoModulesContentAction } from "../../lib/go-parser";

// Mock Buffer.alloc to track what size is being allocated
const originalBufferAlloc = Buffer.alloc;
let allocatedSize: number | undefined;

describe("Go binary processing with large files", () => {
  beforeEach(() => {
    allocatedSize = undefined;
    // Mock Buffer.alloc to capture the size being allocated
    Buffer.alloc = jest.fn((size: number, ...args: any[]) => {
      allocatedSize = size;
      return originalBufferAlloc(size, ...args);
    });
  });

  afterEach(() => {
    // Restore original Buffer.alloc
    Buffer.alloc = originalBufferAlloc;
  });

  test("should only allocate 64KB buffer regardless of file size", async () => {
    // Test with the exact size that caused the customer's issue
    const largeSize = 5472699905; // 5GB+ file size
    
    const largeStream = new Readable({
      read() {
        this.push(null); // End immediately
      }
    });

    // Process the large file
    await getGoModulesContentAction.callback!(largeStream, largeSize);
    
    // Verify that only 64KB was allocated, not the full file size
    expect(allocatedSize).toBe(64 * 1024); // Should be 65536 bytes (64KB)
    expect(allocatedSize).not.toBe(largeSize); // Should NOT be 5GB+
  });

});
