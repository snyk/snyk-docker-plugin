export function isPythonAppFile(filepath: string): boolean {
  return (
    !filepath.includes("/site-packages/") &&
    !filepath.includes("/dist-packages/") &&
    // "/usr/" should not include 1st party code
    !filepath.startsWith("/usr/") &&
    filepath.endsWith(".py")
  );
}
