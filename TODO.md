Open TODOs
=============

Version 3.0
--------------

Version 2.4
-------------

- [ ] Key generation key expiration
- [ ] Key generation documentation
- [ ] Add decryptor.getResult() for decryption result
- [ ] Unit tests: Factor all tests in EncryptionConfig and EncryptWithOpenPGPTestDriver to test the new API
- [ ] Allow to enforce algorithm "minimum level", e.g. for decryption/validation
- [ ] Unit tests: iterate different DefaultPGPAlgorithmSuites.secureSuiteForGnuPG() (incl. compression & no signature!)
- [ ] Extend documentation of key derivation

Version 2.3
-------------
- [x] Bugfixes


Version 2.2
-------------
- [x] Key generation


Version 2.1
-------------

- [x] Code quality reports (Sonar e.g.)
- [x] add .github files
- [x] Add support for Java 11
- [x] Improve test coverage

Version 2.0
-------------

- [x] Remove all TODOs and FIXMEs
- [x] Test sha256,  AES_256
- [x] Move example in dedicated directory + projects
- [x] Document obsolete `secring.gpg` in GPG 2.1  (https://gnupg.org/faq/whats-new-in-2.1.html#nosecring)
- [x] Switch over to Java 8
- [x] Fix links in README
- [x] Add example snippets to README
- [x] Allow `gpg --export -a` and `gpg --export-secret-key -a`  as source for keyring generation

