![Snyk logo](https://snyk.io/style/asset/logo/snyk-print.svg)

***

Snyk helps you find, fix and monitor for known vulnerabilities in your dependencies, both on an ad hoc basis and as part of your CI (Build) system.

| :information_source: This repository is only a plugin to be used with the Snyk CLI tool. To use this plugin to test and fix vulnerabilities in your project, install the Snyk CLI tool first. Head over to [snyk.io](https://github.com/snyk/snyk) to get started. |
| --- |

## Snyk Docker CLI Plugin

This plugin provides dependency metadata for Docker images. 

## Running Tests

To run tests the following environment variables need to be set:

`DOCKER_HUB_PRIVATE_IMAGE`
`DOCKER_HUB_USERNAME`
`DOCKER_HUB_PASSWORD`

`DOCKER_HUB_PRIVATE_IMAGE` should refer to an image that is hosted on Docker Hub but not available publicly. During CI test this is set to `snykgoof/dockergoof:alpine`.