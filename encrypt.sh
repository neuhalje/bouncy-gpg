#!/bin/bash

if [ "x$2" == "x" ]
then
  echo $0 sourceFile destFile
else
java -jar ./build/libs/bouncy-castle-examples-1.0.1-all.jar \
   sender@example.com \
   recipient@example.com \
   ./src/test/resources/sender.gpg.d/pubring.gpg  \
   ./src/test/resources/sender.gpg.d/secring.gpg sender \
   "$1" "$2"
fi

