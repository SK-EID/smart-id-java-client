#!/bin/bash

echo $TRAVIS_PULL_REQUEST
echo $TRAVIS_TAG

if [ "$TRAVIS_PULL_REQUEST" == "false" ] && [ "$TRAVIS_TAG" != "" ]; then
  echo "Starting to publish"
  ./publish.sh
  echo "Finished"
else
  mvn test
  mvn org.owasp:dependency-check-maven:check
  mvn spotbugs:check
fi