#!/bin/bash

# Fail on first error
set -e

echo "Is pull request: $TRAVIS_PULL_REQUEST"
echo "Tag:             $TRAVIS_TAG"
echo "JDK version:     $TRAVIS_JDK_VERSION"

if [ "$TRAVIS_PULL_REQUEST" == "false" ] && [ "$TRAVIS_TAG" != "" ] && [ "$TRAVIS_JDK_VERSION" == "openjdk17" ]; then
  echo "Starting to publish"
  ./publish.sh
  echo "Finished"
elif [ "$TRAVIS_JDK_VERSION" == "openjdk17" ]; then
  ./mvnw test
  ./mvnw -DnvdApiKey="$NVD_key" org.owasp:dependency-check-maven:check
  ./mvnw spotbugs:spotbugs # results should be analyzed before turning back to spotbugs:check
else
  ./mvnw test
fi
