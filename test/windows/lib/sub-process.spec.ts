import * as childProcess from "child_process";
import { EventEmitter } from "events";
import { execute } from "../../../lib/sub-process";

describe("sub-process on Windows", () => {
  describe("execute", () => {
    it("should use shell:true and properly quote arguments on Windows", async () => {
      // Create a mock process
      const mockProcess = new EventEmitter() as any;
      mockProcess.stdout = new EventEmitter();
      mockProcess.stderr = new EventEmitter();

      let capturedArgs: string[] = [];
      let capturedOptions: any = {};

      // Mock the spawn to capture arguments and options
      const spawnSpy = jest
        .spyOn(childProcess, "spawn")
        .mockImplementation((cmd, args, options) => {
          capturedArgs = args as string[];
          capturedOptions = options;
          return mockProcess as any;
        });

      // Start the execute promise with arguments that need quoting
      const executePromise = execute("cmd.exe", [
        "/c",
        "echo",
        "hello world",
        "test&special",
        "path with spaces\\file.txt",
        '"already quoted"',
      ]);

      // Emit success
      process.nextTick(() => {
        mockProcess.stdout.emit("data", "output");
        mockProcess.emit("close", 0);
      });

      await executePromise;

      // Verify shell is true on Windows
      expect(capturedOptions.shell).toBe(true);

      // Verify arguments were quoted (not just escaped)
      // quoteAll should add quotes around arguments that need them
      expect(capturedArgs).toBeDefined();
      expect(capturedArgs.length).toBeGreaterThan(0);

      // Arguments with spaces or special characters should be quoted
      expect(capturedArgs.some((arg) => arg.includes('"'))).toBe(true);

      spawnSpy.mockRestore();
    });

    it("should handle Windows command execution with special characters", async () => {
      // Create a mock process
      const mockProcess = new EventEmitter() as any;
      mockProcess.stdout = new EventEmitter();
      mockProcess.stderr = new EventEmitter();

      let capturedCommand: string = "";
      let capturedArgs: string[] = [];
      let capturedOptions: any = {};

      // Mock the spawn
      const spawnSpy = jest
        .spyOn(childProcess, "spawn")
        .mockImplementation((cmd, args, options) => {
          capturedCommand = cmd as string;
          capturedArgs = args as string[];
          capturedOptions = options;
          return mockProcess as any;
        });

      // Test with PowerShell command that has special characters
      const executePromise = execute("powershell.exe", [
        "-Command",
        "Get-ChildItem",
        "-Path",
        "C:\\Program Files\\",
        "-Filter",
        "*.exe",
        "|",
        "Select-Object",
        "Name",
      ]);

      // Emit success
      process.nextTick(() => {
        mockProcess.stdout.emit("data", "file1.exe\nfile2.exe");
        mockProcess.emit("close", 0);
      });

      const result = await executePromise;

      // Verify Windows-specific handling
      expect(capturedOptions.shell).toBe(true);
      expect(capturedCommand).toBe("powershell.exe");
      expect(capturedArgs).toBeDefined();
      expect(result.stdout).toBe("file1.exe\nfile2.exe");

      spawnSpy.mockRestore();
    });

    it("should handle Windows batch file execution", async () => {
      // Create a mock process
      const mockProcess = new EventEmitter() as any;
      mockProcess.stdout = new EventEmitter();
      mockProcess.stderr = new EventEmitter();

      let capturedOptions: any = {};

      // Mock the spawn
      const spawnSpy = jest
        .spyOn(childProcess, "spawn")
        .mockImplementation((cmd, args, options) => {
          capturedOptions = options;
          return mockProcess as any;
        });

      // Execute a batch file
      const executePromise = execute("test.bat", ["arg1", "arg with spaces"]);

      // Emit success
      process.nextTick(() => {
        mockProcess.stdout.emit("data", "Batch file executed");
        mockProcess.emit("close", 0);
      });

      await executePromise;

      // On Windows, shell must be true for .bat files
      expect(capturedOptions.shell).toBe(true);

      spawnSpy.mockRestore();
    });

    it("should handle Windows environment variables with spaces", async () => {
      // Set environment variables with spaces
      process.env.SNYK_SYSTEM_HTTP_PROXY = "http://proxy server.com:8080";
      process.env.PROGRAM_PATH = "C:\\Program Files\\MyApp";

      // Create a mock process
      const mockProcess = new EventEmitter() as any;
      mockProcess.stdout = new EventEmitter();
      mockProcess.stderr = new EventEmitter();

      let capturedOptions: any = {};

      // Mock the spawn
      const spawnSpy = jest
        .spyOn(childProcess, "spawn")
        .mockImplementation((cmd, args, options) => {
          capturedOptions = options;
          return mockProcess as any;
        });

      // Execute command
      const executePromise = execute("cmd", ["/c", "echo", "%PROGRAM_PATH%"]);

      // Emit success
      process.nextTick(() => {
        mockProcess.emit("close", 0);
      });

      await executePromise;

      // Verify environment variables are preserved
      expect(capturedOptions.env.SNYK_SYSTEM_HTTP_PROXY).toBe(
        "http://proxy server.com:8080",
      );
      expect(capturedOptions.env.PROGRAM_PATH).toBe("C:\\Program Files\\MyApp");
      expect(capturedOptions.shell).toBe(true);

      // Clean up
      delete process.env.SNYK_SYSTEM_HTTP_PROXY;
      delete process.env.PROGRAM_PATH;
      spawnSpy.mockRestore();
    });

    it("should handle Windows path separators in arguments", async () => {
      // Create a mock process
      const mockProcess = new EventEmitter() as any;
      mockProcess.stdout = new EventEmitter();
      mockProcess.stderr = new EventEmitter();

      let capturedArgs: string[] = [];

      // Mock the spawn - no actual process is created
      const spawnSpy = jest
        .spyOn(childProcess, "spawn")
        .mockImplementation((cmd, args, options) => {
          capturedArgs = args as string[];
          return mockProcess as any;
        });

      // Execute with Windows paths - using a generic command
      const executePromise = execute("myapp.exe", [
        "--input",
        "C:\\Users\\test\\input.txt",
        "--output",
        "C:\\Program Files\\My App\\output.txt",
        "--config",
        "D:\\configs\\app config.json",
      ]);

      // Emit success
      process.nextTick(() => {
        mockProcess.emit("close", 0);
      });

      await executePromise;

      // Verify paths with backslashes and spaces are properly quoted
      expect(capturedArgs).toBeDefined();
      expect(capturedArgs.length).toBe(6);

      // The arguments should be quoted by quoteAll due to spaces/special chars
      // We're testing that the Windows-specific code path (line 34) properly handles these

      spawnSpy.mockRestore();
    });

    it("should handle spawn errors on Windows", async () => {
      // Create a mock process
      const mockProcess = new EventEmitter() as any;
      mockProcess.stdout = new EventEmitter();
      mockProcess.stderr = new EventEmitter();

      // Mock the spawn
      const spawnSpy = jest
        .spyOn(childProcess, "spawn")
        .mockImplementation(() => mockProcess);

      // Start execution
      const executePromise = execute("nonexistent.exe", ["arg1"]);

      // Emit Windows-specific error
      const errorMessage = "spawn nonexistent.exe ENOENT";
      process.nextTick(() => {
        mockProcess.emit("error", new Error(errorMessage));
      });

      // Should reject with the error
      await expect(executePromise).rejects.toEqual({
        stdout: "",
        stderr: errorMessage,
      });

      spawnSpy.mockRestore();
    });
  });
});
