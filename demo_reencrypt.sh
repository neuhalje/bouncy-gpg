#!/usr/bin/env bash

#
# decrypts an encrypted ZIP file and reencrypts each file in the zip
#

ASSEMBLY=bouncy-castle-examples-1.0.2
LOCATION=./build

DEST=/tmp/gpg-example-$$

[ -d "${DEST}" ] && rm -rf "${DEST}" 
mkdir $DEST

[ -f ./build/libs/${ASSEMBLY}.jar ] ||  ./gradlew installDist

CP=${LOCATION}/libs/${ASSEMBLY}.jar
for JAR in ${LOCATION}/install/bouncy-castle-examples/lib/*.jar
do
   CP=${CP}:${JAR}
done

java -cp ${CP} \
   name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.MainExplodedSinglethreaded \
   sender@example.com \
   recipient@example.com \
   ./src/test/resources/recipient.gpg.d/pubring.gpg  \
   ./src/test/resources/recipient.gpg.d/secring.gpg recipient \
   "src/test/resources/testdata/large_demo__1GB_data.zip.gpg" "${DEST}"


echo
echo Results in $DEST
