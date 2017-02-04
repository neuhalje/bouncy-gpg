[![Build Status](https://travis-ci.org/neuhalje/bouncy-gpg.svg?branch=master)](https://travis-ci.org/neuhalje/bouncy-gpg)
[![codecov](https://codecov.io/gh/neuhalje/bouncy-gpg/branch/master/graph/badge.svg)](https://codecov.io/gh/neuhalje/bouncy-gpg)
[![license](http://www.wtfpl.net/wp-content/uploads/2012/12/wtfpl-badge-4.png)](http://www.wtfpl.net/)


Mission Statement
=======================

  **Make using [Bouncy Castle](http://bouncycastle.org/) with [OpenPGP](https://tools.ietf.org/html/rfc4880) ~~great~~ fun again!**

This project gives you the following super-powers

- you can encrypt, decrypt, sign and verify GPG/PGP files with just a few lines of code
- you now can protect all the data at rest by reading encrypted files with [transparent GPG decryption](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/openpgp/decrypting/DecryptWithOpenPGPInputStreamFactory.java)
- you can even [decrypt a gpg encrypted ZIP and re-encrypt each file in it again](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/openpgp/example/MainExplodedSinglethreaded.java) -- never again let plaintext hit your servers disk!


Demos
=========

demo_reencrypt.sh
-------------------
A GPG encrypted ZIP file is decrypted on the fly. The structure of the ZIP is then written to disk. All files are re-encrypted before saving them.

* `demo_reencrypt.sh TARGET` -- decrypts an encrypted ZIP file containing  three files (total size: 1.2 GB) AND
   re-encrypts each of the files in the ZIP to the `TARGET` dir.

[The sample](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/openpgp/example/MainExplodedSinglethreaded.java)
shows how e.g. batch jobs can work with large files without leaving plaintext on disk (together with
[Transparent GPG decryption](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/openpgp/decrypting/DecryptWithOpenPGPInputStreamFactory.java)).

This scheme has some very appealing benefits:
* Data in transit is _always_ encrypted with public key cryptography. Indispensable when you have to use `ftp`,
  comforting when you use `https` and the next Heartbleed pops up.
* Data at rest is _always_ encrypted with public key cryptography. When (not if) you get hacked, this can make all the
  difference between _"Move along folks, nothing to see here!"_ and _"I lost confidential customer data to the competition"_.
* You still need to protect the private keys, but this is considerable easier than the alternatives.

Consider the following batch job:

1. The customer sends a large (several GB) GPG encrypted ZIP archive containing a directory structure with several
   data files
2. Your `pre-processing` needs to split up the data for further processing
3. `pre-processing` stream-processes the GPG/ZIP archive
    1. The GPG stream is decrypted using the [DecryptWithOpenPGPInputStreamFactory](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/openpgp/decrypting/DecryptWithOpenPGPInputStreamFactory.java)
    2. The ZIP file is processed with [ExplodeAndReencrypt](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/openpgp/reencryption/ExplodeAndReencrypt.java)
        1. Each file from the archive is [processed](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/openpgp/reencryption/ZipEntityStrategy.java)
        2. And transparently  encrypted with GPG and stored for further processing
4. The `processing` job  [processes](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/openpgp/decrypting/DecryptWithOpenPGPInputStreamFactory.java) the files without writing plaintext to the disk.

encrypt.sh
-----------

* `encrypt.sh  SOURCEFILE DESTFILE` -- uses the testing keys to encrypt a file. Useful for performance measurements.


FAQ
=====

<dl>
  <dt>Why should I use this?</dt>
  <dd>For common use cases this project is easier than vanilla Bouncy Castle. It also has a pretty decent unit test
  coverage. It is free (speech & beer).</dd>

  <dt>Can I just grab a class or two for my project?</dt>
  <dd>Sure! Just grab it and hack away! The code is placed under the <a href="LICENSE">WTPL</a>, you can't get much
   more permissive than this.</dd>

   <dt>Why is the test coverage so low?</dt>
   <dd>Test coverage for 'non-example' code is &gt;85%. Most of the not tested cases are either trivial OR lines that
   throw exceptions when the input format is broken. </dd>

   <dt>How can I contribute?</dt>
   <dd>Pullrequests are welcome!</dd>
   
   <dt>I am getting 'org.bouncycastle.openpgp.PGPException: checksum mismatch ..' exceptions</dt>
   <dd>The passphrase to your private key is very likely wrong (or you did not pass a passphrase).</dd>
</dl>


Building
=======

The project is a basic gradle build. All the scripts use `./gradlew  installDist`

The coverage report (incl. running tests) is generated with `./gradlew check`.

CAVE
=====

* Only one keyring per userid ("sender@example.com") supported.
* Only one signing key per userid supported.

## LICENSE

This code is placed under the WTFPL. Don't forget to adhere to the BouncyCastle License (http://bouncycastle.org/license.html).
