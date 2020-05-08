#!/bin/bash

echo $TRAVIS_PULL_REQUEST
echo $TRAVIS_TAG

if [ "$TRAVIS_PULL_REQUEST" == "false" ] && [ "$TRAVIS_TAG" != "" ]; then
  echo "Starting to publish"
  ./publish.sh
  echo "Finished"
else
  ./mvnw test
  ./mvnw org.owasp:dependency-check-maven:check
  ./mvnw spotbugs:check
fi
