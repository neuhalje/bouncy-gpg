About
======

This repository serves two purposes:
- Showcase the bouncycastle API for OpenPGP en-/decryption
- Demonstrate the impact of buffering on write performance

build
=======

`./gradlew  shadowJar`


Tools
=========

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
