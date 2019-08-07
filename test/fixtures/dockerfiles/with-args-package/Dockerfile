FROM ruby:2.5-alpine AS build-env
ARG RUNTIME_PACKAGES="nodejs bash"
RUN apk update \
  && apk upgrade \
  && apk add --update --no-cache $RUNTIME_PACKAGES
