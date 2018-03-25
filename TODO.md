Open TODOs
=============

Version 2.0
-------------

- [x] Remove all TODOs and FIXMEs
- [x] Test sha256,  AES_256
- [x] Move example in dedicated directory + projects
- [x] Document obsolete secring.gpg in GPG 2.1  (https://gnupg.org/faq/whats-new-in-2.1.html#nosecring)
- [x] Switch over to Java 8
- [x] Fix links in README
- [x] Add example snippets to README
- [x] Allow `gpg --export -a` and `gpg --export-secret-key -a`  as source for keyring generation

Version 2.1
-------------

- [ ] Unit tests: Factor all tests in EncryptionConfig and EncryptWithOpenPGPTestDriver to test the new API
- [ ] Allow to enforce algorithm "minimum level", e.g. for decryption/validation
- [ ] Unit tests: iterate different DefaultPGPAlgorithmSuites.secureSuiteForGnuPG() (incl. compression & no signature!)
- [ ] Code quality reports (Sonar e.g.)
- [ ] Extend documentation of key derivation
- [ ] add .github files

Version 3.0
--------------

