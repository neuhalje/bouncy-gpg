java -jar build/libs/bouncy-castle-examples-1.0.1.jar \
   sender@example.com \
   recipient@example.com \
   ./src/test/resources/sender.gpg.d/pubring.gpg  \
   ./src/test/resources/sender.gpg.d/secring.gpg sender \
   build.gradle build.gradle.enc
