#!/bin/bash

project="smart-id-java-client"

version=$TRAVIS_TAG

staging_url="https://oss.sonatype.org/service/local/staging/deploy/maven2/"
repositoryId="ossrh"

artifact=$project-$version

gpg --import ./private.key

mvn versions:set -DnewVersion=$TRAVIS_TAG

mvn package

gpg -ab pom.xml

cd target

gpg -ab $artifact.jar
gpg -ab $artifact-sources.jar
gpg -ab $artifact-javadoc.jar

jar -cvf bundle.jar ../pom.xml ../pom.xml.asc $artifact.jar $artifact.jar.asc $artifact-javadoc.jar $artifact-javadoc.jar.asc $artifact-sources.jar $artifact-sources.jar.asc

curl -ujorlina2 -u $SONATYPEUN:$SONATYPEPW --request POST -F "file=@bundle.jar" "https://oss.sonatype.org/service/local/staging/bundle_upload"