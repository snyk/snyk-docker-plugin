import type { AnalyzedPackageWithVersion, OSRelease } from "../analyzer/types";
import { ImageName } from "../extractor/image";
import type { DepTree, DepTreeDep } from "../types";

/** @deprecated Should implement a new function to build a dependency graph instead. */
export function buildTree(
  targetImage: string,
  packageFormat: string,
  depInfosList: AnalyzedPackageWithVersion[],
  targetOS: OSRelease,
  imgName?: ImageName,
): DepTree {
  const imageName = imgName ? imgName.name : targetImage;
  // If we don't get an imageName, we never pulled it from a registry, meaning
  // that the image is probably a file on disk. In that case we don't have a
  // version (there would be ways to determine one, but we don't do that.)
  const imageVersion = imgName && imgName.tag ? imgName.tag : "";

  const root: DepTree = {
    // don't use the real image name to avoid scanning it as an issue
    name: "docker-image|" + imageName,
    version: imageVersion,
    targetOS,
    packageFormatVersion: packageFormat + ":0.0.1",
    dependencies: {},
  };

  const depsMap = depInfosList.reduce((acc, depInfo) => {
    const name = depInfo.Name;
    acc[name] = depInfo as AnalyzedPackage;
    return acc;
  }, {} as PackageMap);

  const virtualDepsMap = depInfosList.reduce((acc, depInfo) => {
    const providesNames = depInfo.Provides || [];
    for (const name of providesNames) {
      acc[name] = depInfo as AnalyzedPackage;
    }
    return acc;
  }, {} as PackageMap);

  const depsCounts = {};
  for (const depInfo of depInfosList) {
    countDepsRecursive(
      depInfo.Name,
      new Set(),
      depsMap,
      virtualDepsMap,
      depsCounts,
    );
  }
  const DEP_FREQ_THRESHOLD = 100;
  const tooFrequentDepNames = Object.keys(depsCounts).filter((depName) => {
    return depsCounts[depName] > DEP_FREQ_THRESHOLD;
  });

  const attachDeps = (depInfos: AnalyzedPackageWithVersion[]) => {
    const depNamesToSkip = new Set(tooFrequentDepNames);
    for (const depInfo of depInfos) {
      const subtree = buildTreeRecursive(
        depInfo.Name,
        new Set(),
        depsMap,
        virtualDepsMap,
        depNamesToSkip,
      );
      if (subtree) {
        root.dependencies[subtree.name] = subtree;
      }
    }
  };

  // attach (as direct deps) pkgs not marked auto-installed:
  const manuallyInstalledDeps = depInfosList.filter((depInfo) => {
    return !depInfo.AutoInstalled;
  });
  attachDeps(manuallyInstalledDeps);

  // attach (as direct deps) pkgs marked as auto-installed,
  // but not dependant upon:
  const notVisitedDeps = depInfosList.filter((depInfo) => {
    const depName = depInfo.Name;
    return !depsMap[depName]._visited;
  });
  attachDeps(notVisitedDeps);

  // group all the "too frequest" deps under a meta package:
  if (tooFrequentDepNames.length > 0) {
    const tooFrequentDeps = tooFrequentDepNames.map((name) => {
      return depsMap[name];
    });

    const metaSubtree = {
      name: "meta-common-packages",
      version: "meta",
      dependencies: {},
    };

    for (const depInfo of tooFrequentDeps) {
      const pkg = {
        name: depFullName(depInfo),
        version: depInfo.Version,
      };
      metaSubtree.dependencies[pkg.name] = pkg;
    }

    root.dependencies[metaSubtree.name] = metaSubtree;
  }

  return root;
}

interface AnalyzedPackage extends AnalyzedPackageWithVersion {
  _visited: boolean;
}

interface PackageMap {
  [name: string]: AnalyzedPackage;
}

function buildTreeRecursive(
  depName: string,
  ancestors: Set<string>,
  depsMap: PackageMap,
  virtualDepsMap: PackageMap,
  depNamesToSkip: Set<string>,
): DepTreeDep | null {
  const depInfo = depsMap[depName] || virtualDepsMap[depName];
  if (!depInfo) {
    return null;
  }

  // "realName" as the argument depName might be a virtual pkg
  const realName = depInfo.Name;
  const fullName = depFullName(depInfo);
  if (ancestors.has(fullName) || depNamesToSkip.has(realName)) {
    return null;
  }

  const tree: DepTreeDep = {
    name: fullName,
    version: depInfo.Version,
    dependencies: {},
  };
  if (depInfo._visited) {
    return tree;
  }
  depInfo._visited = true;

  const newAncestors = new Set(ancestors).add(fullName);

  const deps = depInfo.Deps || {};
  for (const name of Object.keys(deps)) {
    const subTree = buildTreeRecursive(
      name,
      newAncestors,
      depsMap,
      virtualDepsMap,
      depNamesToSkip,
    );
    if (subTree) {
      if (!tree.dependencies) {
        tree.dependencies = {};
      }
      if (!tree.dependencies[subTree.name]) {
        tree.dependencies[subTree.name] = subTree;
      }
    }
  }

  return tree;
}

function countDepsRecursive(
  depName: string,
  ancestors: Set<string>,
  depsMap: PackageMap,
  virtualDepsMap: PackageMap,
  depCounts: { [name: string]: number },
) {
  const depInfo = depsMap[depName] || virtualDepsMap[depName];
  if (!depInfo) {
    return;
  }

  // "realName" as the argument depName might be a virtual pkg
  const realName = depInfo.Name;
  if (ancestors.has(realName)) {
    return;
  }

  depCounts[realName] = (depCounts[realName] || 0) + 1;

  const newAncestors = new Set(ancestors).add(realName);
  const deps = depInfo.Deps || {};
  for (const name of Object.keys(deps)) {
    countDepsRecursive(name, newAncestors, depsMap, virtualDepsMap, depCounts);
  }
}

function depFullName(depInfo: AnalyzedPackageWithVersion): string {
  let fullName = depInfo.Name;
  if (depInfo.Source) {
    fullName = depInfo.Source + "/" + fullName;
  }
  return fullName;
}
