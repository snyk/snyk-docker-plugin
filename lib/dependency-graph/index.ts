import { DepGraphBuilder } from "@snyk/dep-graph/dist/core/builder";
import { DepGraph, PkgInfo, PkgManager } from "@snyk/dep-graph/dist/core/types";
import { EventLoopSpinner } from "event-loop-spinner/dist/event-loop-spinner";
import { AnalyzedPackage, Binary, OSRelease } from "../analyzer/types";

export async function buildGraph(
  targetImage: string,
  targetOS: OSRelease,
  packageManagerName: any,
  analyzedPackages: AnalyzedPackage[] | Binary[],
): Promise<DepGraph> {
  const { imageName, imageVersion } = getImageNameAndVersion(targetImage);

  const packageManager: PkgManager = {
    name: packageManagerName,
    repositories: [
      {
        alias: `${targetOS.name}:${targetOS.version}`,
      },
    ],
  };
  const root: PkgInfo = {
    // don't use the real image name to avoid scanning it as an issue
    name: "docker-image|" + imageName,
    version: imageVersion,
  };
  const depGraphBuilder = new DepGraphBuilder(packageManager, root);
  const depInfosList = analyzedPackages as AnalyzedPackage[];

  const depsMap: { [key: string]: AnalyzedPackage } = depInfosList.reduce(
    (acc, depInfo) => {
      const name = depInfo.Name;
      acc[name] = depInfo;
      return acc;
    },
    {},
  );

  const virtualDepsMap: {
    [key: string]: AnalyzedPackage;
  } = depInfosList.reduce((acc, depInfo) => {
    const providesNames = depInfo.Provides || [];
    for (const name of providesNames) {
      acc[name] = depInfo;
    }
    return acc;
  }, {});

  const eventLoopSpinner = new EventLoopSpinner();
  const ancestors = new Set<string>();
  const nodesAddedToGraph = new Set<string>();

  // attach (as direct deps) pkgs not marked auto-installed:
  const manuallyInstalledDeps = depInfosList.filter((depInfo) => {
    return !depInfo.AutoInstalled;
  });
  for (const depInfo of manuallyInstalledDeps) {
    const depName = depInfo.Name;
    await buildGraphRecursive(
      eventLoopSpinner,
      depName,
      depGraphBuilder.rootNodeId,
      depGraphBuilder,
      depsMap,
      virtualDepsMap,
      ancestors,
      nodesAddedToGraph,
    );
  }

  // attach (as direct deps) pkgs marked as auto-installed,
  // but not dependant upon:
  const depsNotAddedToTheGraph = depInfosList.filter((depInfo) => {
    const fullName = depFullName(depInfo);
    const nodeId = `${fullName}@${depInfo.Version}`;
    return !nodesAddedToGraph.has(nodeId);
  });

  for (const depInfo of depsNotAddedToTheGraph) {
    const depName = depInfo.Name;
    await buildGraphRecursive(
      eventLoopSpinner,
      depName,
      depGraphBuilder.rootNodeId,
      depGraphBuilder,
      depsMap,
      virtualDepsMap,
      ancestors,
      nodesAddedToGraph,
    );
  }

  return depGraphBuilder.build();
}

async function buildGraphRecursive(
  eventLoopSpinner: EventLoopSpinner,
  depName: string,
  parentNodeId: string,
  depGraphBuilder: DepGraphBuilder,
  depsMap: { [key: string]: AnalyzedPackage },
  virtualDepsMap: { [key: string]: AnalyzedPackage },
  ancestors: Set<string>,
  nodesAddedToGraph: Set<string>,
): Promise<void> {
  const depInfo = depsMap[depName] || virtualDepsMap[depName];
  if (!depInfo) {
    return;
  }
  const fullName = depFullName(depInfo);
  const nodeId = `${fullName}@${depInfo.Version}`;

  // preventing circular dependencies
  if (ancestors.has(fullName)) {
    return;
  }
  if (nodesAddedToGraph.has(nodeId)) {
    depGraphBuilder.connectDep(parentNodeId, nodeId);
    return;
  }

  depGraphBuilder.addPkgNode(
    { name: fullName, version: depInfo.Version },
    nodeId,
  );
  nodesAddedToGraph.add(nodeId);
  depGraphBuilder.connectDep(parentNodeId, nodeId);
  // dropping
  const newAncestors = new Set(ancestors).add(fullName);

  const deps = depInfo.Deps || {};
  for (const name of Object.keys(deps)) {
    await buildGraphRecursive(
      eventLoopSpinner,
      name,
      nodeId,
      depGraphBuilder,
      depsMap,
      virtualDepsMap,
      newAncestors,
      nodesAddedToGraph,
    );
  }

  if (eventLoopSpinner.isStarving()) {
    await eventLoopSpinner.spin();
  }
}

function depFullName(depInfo) {
  let fullName = depInfo.Name;
  if (depInfo.Source) {
    fullName = depInfo.Source + "/" + fullName;
  }
  return fullName;
}

function getImageNameAndVersion(targetImage) {
  // A tag can only occur in the last section of a docker image name, so
  // check any colon separator after the final '/'. If there are no '/',
  // which is common when using Docker's official images such as
  // "debian:stretch", just check for ':'
  const finalSlash = targetImage.lastIndexOf("/");
  const hasVersion =
    (finalSlash >= 0 && targetImage.slice(finalSlash).includes(":")) ||
    targetImage.includes(":");

  // Defaults for simple images from dockerhub, like "node" or "centos"
  let imageName = targetImage;
  let imageVersion = "latest";

  // If we have a version, split on the last ':' to avoid the optional
  // port on a hostname (i.e. localhost:5000)
  if (hasVersion) {
    const versionSeparator = targetImage.lastIndexOf(":");
    imageName = targetImage.slice(0, versionSeparator);
    imageVersion = targetImage.slice(versionSeparator + 1);
  }

  if (imageName.endsWith(".tar")) {
    imageVersion = "";
  }

  if (imageName.endsWith("@sha256")) {
    imageName = imageName.slice(0, imageName.length - "@sha256".length);
    imageVersion = "";
  }
  return { imageName, imageVersion };
}
