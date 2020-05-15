#!/bin/bash

# Fail on first error
set -e

echo "Is pull request: $TRAVIS_PULL_REQUEST"
echo "Tag:             $TRAVIS_TAG"
echo "JDK version:     $TRAVIS_JDK_VERSION"

if [ "$TRAVIS_PULL_REQUEST" == "false" ] && [ "$TRAVIS_TAG" != "" ] && ["$TRAVIS_JDK_VERSION" == "openjdk8"]; then
  echo "Starting to publish"
  ./publish.sh
  echo "Finished"
elif ["$TRAVIS_JDK_VERSION" == "openjdk8"]; then
  ./mvnw test
  ./mvnw org.owasp:dependency-check-maven:check
  ./mvnw spotbugs:check
else
  ./mvnw test
fi
