import * as childProcess from "child_process";
import { EventEmitter } from "events";
import { execute } from "../../lib/sub-process";

describe("sub-process", () => {
  describe("execute", () => {
    it("should handle spawn errors and set stderr to error message", async () => {
      // Create a mock process that emits an error
      const mockProcess = new EventEmitter() as any;
      mockProcess.stdout = new EventEmitter();
      mockProcess.stderr = new EventEmitter();

      // Mock the spawn to return our mock process
      const spawnSpy = jest
        .spyOn(childProcess, "spawn")
        .mockImplementation(() => mockProcess);

      // Start the execute promise
      const executePromise = execute("nonexistent-command", ["arg1", "arg2"]);

      // Emit an error event (simulating ENOENT when command doesn't exist)
      const errorMessage = "spawn nonexistent-command ENOENT";
      process.nextTick(() => {
        mockProcess.emit("error", new Error(errorMessage));
      });

      // The promise should reject with stdout and stderr
      await expect(executePromise).rejects.toEqual({
        stdout: "",
        stderr: errorMessage,
      });

      // Verify spawn was called correctly
      expect(spawnSpy).toHaveBeenCalledWith(
        "nonexistent-command",
        expect.arrayContaining(["arg1", "arg2"]),
        expect.objectContaining({
          shell: expect.any(Boolean),
          env: expect.any(Object),
        }),
      );

      // Restore the original implementation
      spawnSpy.mockRestore();
    });

    it("should handle normal command execution", async () => {
      // Create a mock process that succeeds
      const mockProcess = new EventEmitter() as any;
      mockProcess.stdout = new EventEmitter();
      mockProcess.stderr = new EventEmitter();

      // Mock the spawn to return our mock process
      const spawnSpy = jest
        .spyOn(childProcess, "spawn")
        .mockImplementation(() => mockProcess);

      // Start the execute promise
      const executePromise = execute("echo", ["hello"]);

      // Emit stdout data and close with success
      process.nextTick(() => {
        mockProcess.stdout.emit("data", "hello\n");
        mockProcess.emit("close", 0);
      });

      // The promise should resolve with stdout
      const result = await executePromise;
      expect(result).toEqual({
        stdout: "hello\n",
        stderr: "",
      });

      // Restore the original implementation
      spawnSpy.mockRestore();
    });

    it("should handle non-zero exit codes", async () => {
      // Create a mock process that exits with error code
      const mockProcess = new EventEmitter() as any;
      mockProcess.stdout = new EventEmitter();
      mockProcess.stderr = new EventEmitter();

      // Mock the spawn to return our mock process
      const spawnSpy = jest
        .spyOn(childProcess, "spawn")
        .mockImplementation(() => mockProcess);

      // Start the execute promise
      const executePromise = execute("false", []);

      // Emit stderr data and close with error code
      process.nextTick(() => {
        mockProcess.stderr.emit("data", "Command failed");
        mockProcess.emit("close", 1);
      });

      // The promise should reject with stdout and stderr
      await expect(executePromise).rejects.toEqual({
        stdout: "",
        stderr: "Command failed",
      });

      // Restore the original implementation
      spawnSpy.mockRestore();
    });

    it("should handle proxy environment variables", async () => {
      // Set proxy environment variables
      process.env.SNYK_SYSTEM_HTTP_PROXY = "http://proxy.example.com:8080";
      process.env.SNYK_SYSTEM_HTTPS_PROXY = "https://proxy.example.com:8443";
      process.env.SNYK_SYSTEM_NO_PROXY = "localhost,127.0.0.1";

      // Create a mock process
      const mockProcess = new EventEmitter() as any;
      mockProcess.stdout = new EventEmitter();
      mockProcess.stderr = new EventEmitter();

      // Mock the spawn to capture the options
      let capturedOptions: any;
      const spawnSpy = jest
        .spyOn(childProcess, "spawn")
        .mockImplementation((cmd, args, options) => {
          capturedOptions = options;
          return mockProcess as any;
        });

      // Start the execute promise
      const executePromise = execute("echo", ["test"]);

      // Close with success
      process.nextTick(() => {
        mockProcess.emit("close", 0);
      });

      await executePromise;

      // Verify proxy environment variables were set
      expect(capturedOptions.env.HTTP_PROXY).toBe(
        "http://proxy.example.com:8080",
      );
      expect(capturedOptions.env.HTTPS_PROXY).toBe(
        "https://proxy.example.com:8443",
      );
      expect(capturedOptions.env.NO_PROXY).toBe("localhost,127.0.0.1");

      // Clean up
      delete process.env.SNYK_SYSTEM_HTTP_PROXY;
      delete process.env.SNYK_SYSTEM_HTTPS_PROXY;
      delete process.env.SNYK_SYSTEM_NO_PROXY;
      spawnSpy.mockRestore();
    });
  });
});
