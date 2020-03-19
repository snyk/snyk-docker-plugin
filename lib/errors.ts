import * as Debug from "debug";

const debug = Debug("snyk");

export function tryGetAnalysisError(error, targetImage: string): Error {
  if (typeof error === "string") {
    debug(`Error while running analyzer: '${error}'`);
    handleCommonErrors(error, targetImage);
    let errorMsg = error;
    const errorMatch = /msg="(.*)"/g.exec(errorMsg);
    if (errorMatch) {
      errorMsg = errorMatch[1];
    }
    return new Error(errorMsg);
  }

  return error;
}

function handleCommonErrors(error: string, targetImage: string): void {
  if (error.indexOf("command not found") !== -1) {
    throw new Error("Snyk docker CLI was not found");
  }
  if (error.indexOf("Cannot connect to the Docker daemon") !== -1) {
    throw new Error(
      "Cannot connect to the Docker daemon. Is the docker" + " daemon running?",
    );
  }
  const ERROR_LOADING_IMAGE_STR = "Error loading image from docker engine:";
  if (error.indexOf(ERROR_LOADING_IMAGE_STR) !== -1) {
    if (error.indexOf("reference does not exist") !== -1) {
      throw new Error(`Docker image was not found locally: ${targetImage}`);
    }
    if (error.indexOf("permission denied while trying to connect") !== -1) {
      let errString = error.split(ERROR_LOADING_IMAGE_STR)[1];
      errString = (errString || "").slice(0, -2); // remove trailing \"
      throw new Error(
        "Permission denied connecting to docker daemon. " +
          "Please make sure user has the required permissions. " +
          "Error string: " +
          errString,
      );
    }
  }
  if (error.indexOf("Error getting docker client:") !== -1) {
    throw new Error("Failed getting docker client");
  }
  if (error.indexOf("Error processing image:") !== -1) {
    throw new Error("Failed processing image:" + targetImage);
  }
}
