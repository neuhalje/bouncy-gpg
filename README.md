[![Build Status](https://travis-ci.org/neuhalje/bouncy-castle-gpg-examples.svg?branch=master)](https://travis-ci.org/neuhalje/bouncy-castle-gpg-examples)
[![codecov](https://codecov.io/gh/neuhalje/bouncy-castle-gpg-examples/branch/master/graph/badge.svg)](https://codecov.io/gh/neuhalje/bouncy-castle-gpg-examples)


About
======

This repository serves several facets:

- Showcase the bouncycastle API for OpenPGP en-/decryption
- Provide examples to [decrypt an enencrypted ZIP and re-encrypt each file in it again](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/example/MainExplodedSinglethreaded.java)
- Streams with [transparent GPG decryption](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/decrypting/DecryptWithOpenPGPInputStreamFactory.java)
- Demonstrate the impact of buffering on write performance (this was the original intend of this repo. How times change.
  See [here](https://github.com/neuhalje/finding_bottlenecks_example) for better sample code).

TODO
-----
PR & comments welcome!

- [ ] Cleanup code: Remove code duplications
- [ ] Cleanup code: Create a more uniform API
- [ ] Cleanup code: Better error handling
- [ ] Document: Better documentation
- [ ] Tests: Better test coverage esp. for the _unhappy paths_

build
=======

The project is a basic gradle build. All the scripts use `./gradlew  installDist`

The coverage report (incl. running tests) is generated with `./gradlew check`.


Demos
=========

demo_reencrypt.sh
-------------------
A GPG encrypted ZIP file is decrypted on the fly. The structure of the ZIP is then written to disk. All files are re-encrypted before saving them.

* `demo_reencrypt.sh TARGET` -- decrypts an encrypted ZIP file containing  three files (total size: 1.2 GB) AND 
   re-encrypts each of the files in the ZIP to the `TARGET` dir.

[The sample](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/example/MainExplodedSinglethreaded.java)
shows how e.g. batch jobs can work with large files without leaving plaintext on disk (together with
[Transparent GPG decryption](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/decrypting/DecryptWithOpenPGPInputStreamFactory.java)).

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
    1. The GPG stream is decrypted using the [DecryptWithOpenPGPInputStreamFactory](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/decrypting/DecryptWithOpenPGPInputStreamFactory.java)
    2. The ZIP file is processed with [ExplodeAndReencrypt](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/reencryption/ExplodeAndReencrypt.java)
        1. Each file from the archive is [processed](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/reencryption/ZipEntityStrategy.java)
        2. And transparently  encrypted with GPG and stored for further processing
4. The `processing` job  [processes](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/decrypting/DecryptWithOpenPGPInputStreamFactory.java) the files without writing plaintext to the disk.

encrypt.sh
-----------

* `encrypt.sh  SOURCEFILE DESTFILE` -- uses the testing keys to encrypt a file. Useful for performance measurements.

Performance Results
===================


See [Main.java](./src/main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/example/Main.java):

| Buffering              | source file size   | duration | throughput|write IO/s (1)| write syscalls (2) |
|------------------------|-------------------:|---------:|----------:|-------------:|---------------------:|
| 8 KiB output buffering |  50 MB             |    5s    | 10.0 MB/s |              |                      |
| 8 KiB output buffering | 200 MB             |   21s    |  9.5 MB/s |              |           1,652 /s   |
| 8 KiB output buffering | 500 MB             |   52s    |  9.8 MB/s |  15          |          ~2,100 /s   |
| 8 KiB output buffering | 800 MB             |   80s    | 10.0 MB/s |              |                      |

0. All tests executed on a Core i7, 8GB RAM, SSD
1. Average write IO/s over time (estimated via iotop)
2. Average number of syscalls to `write`
3. very slow, probably because the laptop had been used otherwise


## LICENSE

This code is placed under the WTFPL. Don't forget to adhere to the BouncyCastle License (http://bouncycastle.org/license.html).
