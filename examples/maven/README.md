Maven Example
================

- `settings.xml` activates JCenter (if not already enabled -- see https://maven.apache.org/settings.html)


Running
==========

```sh
mvn compile

# ...

mvn exec:java -Dexec.mainClass="name.neuhalfen.projects.crypto.bouncycastle.openpgp.example.maven.App"
```
