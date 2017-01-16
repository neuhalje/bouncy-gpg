About
======

This repository serves several purposes:

- Showcase the bouncycastle API for OpenPGP en-/decryption
- Provide examples to [decrypt an enencrypted ZIP and re-encrypt each file in it again](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/MainExplodedSinglethreaded.java)
- Streams with [transparent GPG decryption](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/decrypting/DecryptWithOpenPGPInputStreamFactory.java)
- Demonstrate the impact of buffering on write performance (this was the original intend of this repo. How times change.
  See [here](https://github.com/neuhalje/finding_bottlenecks_example) for better sample code).

build
=======

The project is a basic gradle build. All the scripts use `./gradlew  installDist`


Demos
=========

demo_reencrypt.sh
-------------------
A GPG encrypted ZIP file is decrypted on the fly. The structure of the ZIP is then written to disk. All files are re-encrypted before saving them.

* `demo_reencrypt.sh TARGET` -- decrypts an encrypted ZIP file containing  three files (total size: 1.2 GB) AND 
   re-encrypts each of the files in the ZIP to the `TARGET` dir.

[The sample](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/MainExplodedSinglethreaded.java)
shows how e.g. batch jobs can work with large files without leaving plaintext on disk (together with
[Transparent GPG decryption](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/decrypting/DecryptWithOpenPGPInputStreamFactory.java)).

This scheme has some very appealing benefits:
* Data in transit is _always_ encrypted with public key cryptography. Indispensable when you have to use `ftp`,
  comforting when you use `https` and the next Heartbleed pops up.
* Data at rest is _always_ encrypted with public key cryptography. When (not if) you get hacked, this can make all the
  difference between _"Move along folks, nothing to see here!"_ and _"I lost confidential customer data to the competition"_.
* You still need to protect the private keys, but this is considerable easier than the alternatives.

Consider the following batch job:

1) The customer sends a large (several GB) GPG encrypted ZIP archive containing a directory structure with several 
   data files
2) Your `pre-processing` needs to split up the data for further processing
3) `pre-processing` stream-processes the GPG/ZIP archive
    1) The GPG stream is decrypted using the [DecryptWithOpenPGPInputStreamFactory](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/decrypting/DecryptWithOpenPGPInputStreamFactory.java)
    2) The ZIP file is processed with [ExplodeAndReencrypt](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/reencryption/ExplodeAndReencrypt.java)
        1) Each file from the archive is [processed](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/reencryption/ZipEntityStrategy.java)
        2) And transparently  encrypted with GPG and stored for further processing
4) The `processing` job  [processes](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/decrypting/DecryptWithOpenPGPInputStreamFactory.java) the files without writing plaintext to the disk.

encrypt.sh
-----------

* `encrypt.sh [buffered|unbuffered] SOURCEFILE DESTFILE` -- uses the testing keys to encrypt a file. Useful for performance measurements.
* `encrypt_count_syscalls.sh [buffered|unbuffered] SOURCEFILE DESTFILE` -- like above but uses SystemTap to count syscalls (needs sudo and the systemtap packages installed).

SystemTap scripts
----------------

[SystemTap](https://www.sourceware.org/systemtap) gives intimate access to Linux kernel internals (basically like Solaris DTrace). In this demo two scripts where used to compare syscall counts in buffered vs. unbuffered variants.

*  `util/syscall_count_by_process.stp` - Counts the number of syscalls per process name. Can be used to get an idea if your implementation issues substantial more/less syscalls than other processes (e.g. the gpg binary)
* `util/topsys_per_process.stp` -  prints out the  which systemcalls a process used how often (top 20)  


### Installing SystemTap

This is not quite scope of the demo. Visit [this page](https://sourceware.org/systemtap/getinvolved.html) for installation and the [beginners guide](https://www.sourceware.org/systemtap/SystemTap_Beginners_Guide) for first steps.

Performance Results
===================

Buffering via `BufferedOutputStream` makes a huge performance impact because it cuts down syscall count to approx 1/60th and below.

See [Main.java](./src/main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/Main.java):

| Buffering              | source file size   | duration | throughput|write IO/s (1)| write syscalls (2) |
|------------------------|-------------------:|---------:|----------:|-------------:|---------------------:|
| No output buffering    |  50 MB             |   97s    |  0.5 MB/s |              |                      |
| No output buffering    | 200 MB             | 2457s (3)|  0.08 MB/s|              |        ~115,600/s    |
| No output buffering    | 500 MB             | 1130s    |  0.4 MB/s |   3          |        ~125,000/s    |
| No output buffering    | 800 MB             | 1809s    |  0.4 MB/s |              |                      |
| 8 KiB output buffering |  50 MB             |    5s    | 10.0 MB/s |              |                      |
| 1 MiB output buffering |  50 MB             |    5s    | 10.0 MB/s |              |                      |
| 8 KiB output buffering | 200 MB             |   21s    |  9.5 MB/s |              |           1,652 /s   |
| 8 KiB output buffering | 500 MB             |   52s    |  9.8 MB/s |  15          |          ~2,100 /s   |
| 8 KiB output buffering | 800 MB             |   80s    | 10.0 MB/s |              |                      |
| 1 MiB output buffering | 800 MB             |   82s    |  9.7 MB/s |              |                      |

0) All tests executed on a Core i7, 8GB RAM, SSD
1) Average write IO/s over time (estimated via iotop)
2) Average number of syscalls to `write`
3) very slow, probably because the laptop had been used otherwise


## LICENSE

This code is placed under the WTFPL. Don't forget to adhere to the BouncyCastle License (http://bouncycastle.org/license.html).
