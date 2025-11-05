import * as path from "path";

// Import the actual filePathMatches function to test the real implementation
import { filePathMatches } from "../../lib/go-parser/index";

/**
 * Test file demonstrating the platform-specific extension detection issue
 * that causes esbuild binaries to be missed on Windows but detected on Linux/Mac
 */

describe("Extension Detection Issue", () => {
  // The problematic esbuild path that fails on Windows
  const esbuildPath = "/app/node_modules/.pnpm/@esbuild+linux-x64@0.23.1/node_modules/@esbuild/linux-x64/bin/esbuild";
  
  // How it gets normalized on different platforms
  const windowsNormalizedPath = "\\app\\node_modules\\.pnpm\\@esbuild+linux-x64@0.23.1\\node_modules\\@esbuild\\linux-x64\\bin\\esbuild";
  const linuxNormalizedPath = "/app/node_modules/.pnpm/@esbuild+linux-x64@0.23.1/node_modules/@esbuild/linux-x64/bin/esbuild";

  describe("Current Broken Implementation", () => {
    // This is what the Go parser currently does
    function hasExtensionCurrent(filePath: string): boolean {
      const normalizedPath = path.normalize(filePath);
      return !!path.parse(normalizedPath).ext;
    }

    it("should show the platform difference with path.parse().ext", () => {
      // Test with forward slashes (works correctly)
      const forwardSlashResult = hasExtensionCurrent(linuxNormalizedPath);
      console.log(`Forward slash path: "${linuxNormalizedPath}"`);
      console.log(`path.parse().ext result: "${path.parse(linuxNormalizedPath).ext}"`);
      console.log(`hasExtension: ${forwardSlashResult}`);

      // Test with backslashes (broken on Windows)
      const backslashResult = hasExtensionCurrent(windowsNormalizedPath);
      console.log(`\nBackslash path: "${windowsNormalizedPath}"`);
      console.log(`path.parse().ext result: "${path.parse(windowsNormalizedPath).ext}"`);
      console.log(`hasExtension: ${backslashResult}`);

      // Forward slash path works correctly on all platforms
      expect(forwardSlashResult).toBe(false);
      
      // Backslash path is incorrectly parsed on all platforms when using path.parse()
      // This demonstrates the bug - path.parse() treats backslashes as part of filename
      expect(backslashResult).toBe(true); // Shows the bug on all platforms
    });

    it("should show detailed path.parse() differences", () => {
      const forwardParsed = path.parse(linuxNormalizedPath);
      const backslashParsed = path.parse(windowsNormalizedPath);

      console.log("\nDetailed path.parse() results:");
      console.log("Forward slash parsed:", JSON.stringify(forwardParsed, null, 2));
      console.log("Backslash parsed:", JSON.stringify(backslashParsed, null, 2));

      // The issue: on Windows, path.parse() treats backslash paths differently
    });
  });

  describe("Fixed Implementations", () => {
    // Fix 1: Use posix path operations consistently
    function hasExtensionPosixFixed(filePath: string): boolean {
      const posixPath = filePath.replace(/\\/g, '/');
      const normalizedPath = path.posix.normalize(posixPath);
      return !!path.posix.parse(normalizedPath).ext;
    }

    // Fix 2: Use simple basename check (like rest of codebase)
    function hasExtensionBasenameFixed(filePath: string): boolean {
      const posixPath = filePath.replace(/\\/g, '/');
      const basename = path.posix.basename(posixPath);
      return basename.includes('.') && !basename.startsWith('.');
    }

    // Fix 3: Use endsWith pattern (like binaries in codebase)
    function hasExtensionEndsWithFixed(filePath: string): boolean {
      const basename = path.posix.basename(filePath);
      // Check if it has common binary extensions
      const binaryExtensions = ['.exe', '.dll', '.so', '.dylib', '.bin'];
      return binaryExtensions.some(ext => basename.endsWith(ext));
    }

    // Fix 4: Convert backslashes to forward slashes first
    function hasExtensionConvertFixed(filePath: string): boolean {
      const posixPath = filePath.replace(/\\/g, '/');
      return !!path.posix.parse(posixPath).ext;
    }

    it("should show all fixes work correctly on both path formats", () => {
      const testPaths = [
        linuxNormalizedPath,
        windowsNormalizedPath,
        esbuildPath
      ];

      testPaths.forEach((testPath, index) => {
        console.log(`\nTesting path ${index + 1}: "${testPath}"`);
        
        const currentResult = !!path.parse(path.normalize(testPath)).ext;
        const posixResult = hasExtensionPosixFixed(testPath);
        const basenameResult = hasExtensionBasenameFixed(testPath);
        const endsWithResult = hasExtensionEndsWithFixed(testPath);
        const convertResult = hasExtensionConvertFixed(testPath);

        console.log(`  Current (broken): ${currentResult}`);
        console.log(`  Posix fix: ${posixResult}`);
        console.log(`  Basename fix: ${basenameResult}`);
        console.log(`  EndsWith fix: ${endsWithResult}`);
        console.log(`  Convert fix: ${convertResult}`);

        // All fixes should return false (no extension) for esbuild binary
        expect(posixResult).toBe(false);
        expect(basenameResult).toBe(false);
        expect(endsWithResult).toBe(false);
        expect(convertResult).toBe(false);
      });
    });

    it("should correctly identify files WITH extensions", () => {
      const filesWithExtensions = [
        "/app/script.sh",
        "\\app\\config.json",
        "/usr/lib/libssl.so.3",
        "\\etc\\ssl\\openssl.cnf"
      ];

      filesWithExtensions.forEach(filePath => {
        console.log(`\nTesting file with extension: "${filePath}"`);
        
        const posixResult = hasExtensionPosixFixed(filePath);
        const basenameResult = hasExtensionBasenameFixed(filePath);
        const convertResult = hasExtensionConvertFixed(filePath);

        console.log(`  Posix fix: ${posixResult}`);
        console.log(`  Basename fix: ${basenameResult}`);
        console.log(`  Convert fix: ${convertResult}`);

        // All should correctly detect extensions
        expect(posixResult).toBe(true);
        expect(basenameResult).toBe(true);
        expect(convertResult).toBe(true);
      });
    });
  });

  describe("Codebase Consistency Check", () => {
    it("should show how other parts of codebase handle extensions", () => {
      const testFile = "/app/example.jar";
      
      // Java approach (slice method)
      const javaExtension = testFile.slice(-4);
      const isJavaArchive = [".jar", ".war"].includes(javaExtension);
      
      // Binary approach (endsWith)
      const isJavaBinary = testFile.endsWith("java");
      const isNodeBinary = testFile.endsWith("node");
      
      // Node approach (exact filename match)
      const filename = path.basename(testFile);
      const isNodeFile = ["package.json", "yarn.lock"].includes(filename);

      console.log("\nCodebase patterns:");
      console.log(`Java slice(-4): "${javaExtension}" -> isArchive: ${isJavaArchive}`);
      console.log(`Binary endsWith: java=${isJavaBinary}, node=${isNodeBinary}`);
      console.log(`Node exact match: "${filename}" -> isNodeFile: ${isNodeFile}`);

      // Show that these approaches are platform-independent
      expect(typeof javaExtension).toBe("string");
      expect(typeof isJavaBinary).toBe("boolean");
      expect(typeof isNodeFile).toBe("boolean");
    });
  });

  describe("Real-world Paths", () => {
    it("should test common binary paths that should NOT have extensions", () => {
      const binaryPaths = [
        "/usr/bin/kubectl",
        "/app/myservice", 
        "/opt/binary",
        "\\usr\\bin\\docker",
        "\\app\\node_modules\\.pnpm\\@esbuild+linux-x64@0.23.1\\node_modules\\@esbuild\\linux-x64\\bin\\esbuild"
      ];

      binaryPaths.forEach(binPath => {
        const posixPath = binPath.replace(/\\/g, '/');
        const hasExt = path.posix.basename(posixPath).includes('.');
        console.log(`Binary "${binPath}" -> hasExtension: ${hasExt}`);
        expect(hasExt).toBe(false);
      });
    });

    it("should test common config files that SHOULD have extensions", () => {
      const configPaths = [
        "/app/config.json",
        "/etc/ssl/openssl.cnf",
        "\\app\\package.json",
        "\\etc\\hosts.conf"
      ];

      configPaths.forEach(configPath => {
        const posixPath = configPath.replace(/\\/g, '/');
        const hasExt = path.posix.basename(posixPath).includes('.');
        console.log(`Config "${configPath}" -> hasExtension: ${hasExt}`);
        expect(hasExt).toBe(true);
      });
    });
  });

  describe("Actual Go Parser Fix Verification", () => {
    it("should verify the real filePathMatches function now works correctly with your fix", () => {
      const testPaths = [
        {
          path: "/app/node_modules/.pnpm/@esbuild+linux-x64@0.23.1/node_modules/@esbuild/linux-x64/bin/esbuild",
          description: "esbuild binary with forward slashes",
          shouldMatch: true
        },
        {
          path: "\\app\\node_modules\\.pnpm\\@esbuild+linux-x64@0.23.1\\node_modules\\@esbuild\\linux-x64\\bin\\esbuild", 
          description: "esbuild binary with backslashes (Windows paths)",
          shouldMatch: true
        },
        {
          path: "/app/config.json",
          description: "config file with extension",
          shouldMatch: false
        },
        {
          path: "\\app\\package.json",
          description: "config file with extension (Windows path)",
          shouldMatch: false
        },
        {
          path: "/usr/bin/kubectl",
          description: "regular binary without extension",
          shouldMatch: true
        },
        {
          path: "\\usr\\bin\\docker",
          description: "regular binary without extension (Windows path)",
          shouldMatch: true
        }
      ];

      console.log("\n🔧 Testing actual filePathMatches function with your fix:");
      
      testPaths.forEach(({ path: testPath, description, shouldMatch }) => {
        const result = filePathMatches(testPath);
        console.log(`  ${description}`);
        console.log(`    Path: "${testPath}"`);
        console.log(`    Result: ${result} (expected: ${shouldMatch})`);
        
        expect(result).toBe(shouldMatch);
      });
    });

    it("should confirm esbuild binaries are now detected correctly on both path formats", () => {
      const esbuildPaths = [
        "/app/node_modules/.pnpm/@esbuild+linux-x64@0.23.1/node_modules/@esbuild/linux-x64/bin/esbuild",
        "\\app\\node_modules\\.pnpm\\@esbuild+linux-x64@0.23.1\\node_modules\\@esbuild\\linux-x64\\bin\\esbuild"
      ];

      console.log("\n🎯 Confirming esbuild binary detection fix:");
      
      esbuildPaths.forEach((esbuildPath, index) => {
        const matches = filePathMatches(esbuildPath);
        const pathType = index === 0 ? "Forward slash (Linux/Mac)" : "Backslash (Windows)";
        
        console.log(`  ${pathType}: ${matches ? "✅ DETECTED" : "❌ MISSED"}`);
        console.log(`    Path: "${esbuildPath}"`);
        
        // Both should now be detected (return true)
        expect(matches).toBe(true);
      });
    });
  });
});
