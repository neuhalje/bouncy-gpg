#!/bin/bash

if [ "x$3" == "x" ]
then
  echo $0 "[buffered|unbuffered] sourceFile destFile"
else
CMD="java -jar ./build/libs/bouncy-castle-examples-1.0.1-all.jar \
   \"$1\" \
   sender@example.com \
   recipient@example.com \
   ./src/test/resources/sender.gpg.d/pubring.gpg  \
   ./src/test/resources/sender.gpg.d/secring.gpg sender \
   \"$2\" \"$3\"" 
sudo stap util/topsys_per_process.stp -c "$CMD"
fi

