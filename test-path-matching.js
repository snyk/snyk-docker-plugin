// Test to reproduce the Windows path matching issue
const path = require('path');

// Simulate the ignoredPaths from Go parser
const ignoredPaths = [
  "/boot",
  "/dev", 
  "/etc",
  "/home",
  "/media",
  "/mnt",
  "/proc",
  "/root",
  "/run",
  "/sbin",
  "/sys",
  "/tmp",
  "/var"
].map(p => path.normalize(p));

// The esbuild path from the container
const linuxPath = "/app/node_modules/.pnpm/@esbuild+linux-x64@0.23.1/node_modules/@esbuild/linux-x64/bin/esbuild";

// Simulate what happens on different platforms
function testPathMatching(filePath, platform) {
  // Simulate path.join(path.sep, headers.name) from layer.ts
  const absoluteFileName = path.join(path.sep, filePath);
  
  // Simulate the Go parser logic
  const normalizedPath = path.normalize(absoluteFileName);
  const dirName = path.dirname(normalizedPath);
  
  console.log(`\n--- Testing on ${platform} ---`);
  console.log(`Original path: ${filePath}`);
  console.log(`Absolute path: ${absoluteFileName}`);
  console.log(`Normalized: ${normalizedPath}`);
  console.log(`Directory: ${dirName}`);
  console.log(`Ignored paths: ${JSON.stringify(ignoredPaths)}`);
  
  // Check if file has extension (should be false for binaries)
  // OLD WAY (buggy on Windows):
  const hasExtensionOld = !!path.parse(normalizedPath).ext;
  console.log(`Has extension (old way): ${hasExtensionOld}`);
  console.log(`  filename parsed:`, path.parse(normalizedPath));

  // Check if path is ignored
  const isIgnoredOld = ignoredPaths.some((ignorePath) => dirName.startsWith(ignorePath));
  console.log(`Is ignored: ${isIgnoredOld} (checking if '${dirName}' starts with any ignored path)`);
  
  // Final result: should this file be processed as a Go binary?
  const shouldMatchOld = !hasExtensionOld && !isIgnoredOld;
  console.log(`Should match Go binary: ${shouldMatchOld}`);
  
  // NEW WAY (fixed):
  const fileName = path.basename(filePath);
  const hasExtension = !!path.parse(fileName).ext;
  console.log(`Has extension (new way): ${hasExtension} (checking filename: '${fileName}')`);
  console.log(`  filename parsed:`, path.parse(fileName));
  
  // Check if path is ignored
  const isIgnored = ignoredPaths.some((ignorePath) => dirName.startsWith(ignorePath));
  console.log(`Is ignored: ${isIgnored} (checking if '${dirName}' starts with any ignored path)`);
  
  // Final result: should this file be processed as a Go binary?
  const shouldMatch = !hasExtension && !isIgnored;
  console.log(`Should match Go binary: ${shouldMatch}`);
  
  return shouldMatch;
}

// Test on current platform (Mac/Linux)
testPathMatching(linuxPath, process.platform);

// Simulate Windows behavior by manipulating the path separator
// This is what would happen when path.join(path.sep, headers.name) runs on Windows
if (process.platform !== 'win32') {
  console.log('\n=== SIMULATING WINDOWS BEHAVIOR ===');
  
  // Temporarily override path separator behavior
  const originalSep = path.sep;
  const originalJoin = path.join;
  const originalNormalize = path.normalize;
  const originalDirname = path.dirname;
  
  // Mock Windows path behavior
  Object.defineProperty(path, 'sep', { value: '\\', configurable: true });
  path.join = (...args) => args.join('\\').replace(/\//g, '\\');
  path.normalize = (p) => p.replace(/\//g, '\\').replace(/\\+/g, '\\');
  path.dirname = (p) => {
    const normalized = p.replace(/\//g, '\\');
    const parts = normalized.split('\\');
    return parts.slice(0, -1).join('\\');
  };
  
  testPathMatching(linuxPath, 'win32 (simulated)');
  
  // Restore original functions
  Object.defineProperty(path, 'sep', { value: originalSep, configurable: true });
  path.join = originalJoin;
  path.normalize = originalNormalize;
  path.dirname = originalDirname;
}
