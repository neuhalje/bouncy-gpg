#!/usr/bin/env bash

ASSEMBLY=bouncy-castle-examples-2.0.0
LOCATION=./build

[ -f ./build/libs/${ASSEMBLY}.jar ] ||  ./gradlew installDist

if [ "x$2" == "x" ]
then
  echo "$0  sourceFile destFile"
else

CP=${LOCATION}/libs/${ASSEMBLY}.jar
for JAR in ${LOCATION}/install/bouncy-castle-examples/lib/*.jar
do
   CP=${CP}:${JAR}
done

java -cp ${CP} \
   name.neuhalfen.projects.crypto.bouncycastle.openpgp.example.DecryptMain \
   ./src/test/resources/recipient.gpg.d/pubring.gpg  \
   ./src/test/resources/recipient.gpg.d/secring.gpg recipient \
   "$1" "$2"
fi

