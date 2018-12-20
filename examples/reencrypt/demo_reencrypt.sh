#!/usr/bin/env bash

#
# decrypts an encrypted ZIP file and reencrypts each file in the zip
#

ASSEMBLY=bouncy-gpg-example-reencryption-1.0.0
LOCATION=./build

DRIVER_CLASS=name.neuhalfen.projects.crypto.bouncycastle.openpgp.example.MainExplodedSinglethreaded

DEST=/tmp/gpg-example-$$

[ -d "${DEST}" ] && rm -rf "${DEST}"
mkdir $DEST || exit 1
echo Writing results into \"$DEST\"

[ -f ./build/libs/${ASSEMBLY}.jar ] ||  ./gradlew installDist

CP=${LOCATION}/libs/${ASSEMBLY}.jar
for JAR in ${LOCATION}/install/bouncy-gpg-example-reencryption/lib/*.jar
do
   CP=${CP}:${JAR}
done

# The example source files are encrypted TO recipient@example.com (that is why the recipients keyring is used)
# The generated files are also encrypted to recipient (and signed by recipient)
time java -cp ${CP} \
   ${DRIVER_CLASS} \
   recipient@example.com \
   recipient@example.com \
   ../../src/test/resources/recipient.gpg.d/pubring.gpg  \
   ../../src/test/resources/recipient.gpg.d/secring.gpg recipient \
   ../../src/test/resources/testdata/large_demo__1GB_data.zip.gpg "${DEST}"

echo
echo Results in $DEST
