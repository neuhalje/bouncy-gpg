#!/usr/bin/env bash

ASSEMBLY=bouncy-castle-examples-1.0.2
LOCATION=./build

[ -f ./build/libs/${ASSEMBLY}.jar ] ||  ./gradlew installDist

if [ "x$3" == "x" ]
then
  echo "$0 [buffered|unbuffered] sourceFile destFile"
else

CP=${LOCATION}/libs/${ASSEMBLY}.jar
for JAR in ${LOCATION}/install/bouncy-castle-examples/lib/*.jar
do
   CP=${CP}:${JAR}
done

CMD="java -cp ${CP} \
   name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.Main \
   \"$1\" \
   sender@example.com \
   recipient@example.com \
   ./src/test/resources/sender.gpg.d/pubring.gpg  \
   ./src/test/resources/sender.gpg.d/secring.gpg sender \
   \"$2\" \"$3\""

sudo stap util/topsys_per_process.stp -c "$CMD"

fi
