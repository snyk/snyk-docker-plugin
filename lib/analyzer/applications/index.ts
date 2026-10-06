import { dotnetFilesToScannedProjects } from "./dotnet";
import { nodeFilesToScannedProjects } from "./node";
import { phpFilesToScannedProjects } from "./php";
import {
  pipFilesToScannedProjects,
  poetryFilesToScannedProjects,
} from "./python";
import { cargoFilesToScannedProjects } from "./rust";

export {
  cargoFilesToScannedProjects,
  dotnetFilesToScannedProjects,
  nodeFilesToScannedProjects,
  phpFilesToScannedProjects,
  poetryFilesToScannedProjects,
  pipFilesToScannedProjects,
};
