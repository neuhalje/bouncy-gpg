build
=======

`./gradlew  shadowJar`


Tools
=========

`encrypt.sh SOURCEFILE DESTFILE` -- uses the testing keys to encrypt a file. Usefull for performance measurements.

Performance Results
===================

Buffering via `BufferedOutputStream` makes a huge performance impact because it cuts down syscall count to approx 1/50th.

See [Main.java](./src/main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/Main.java):

| Buffering              | source file size   | duration | throughput|write IO/s *| write syscalls/s ** |
|------------------------|-------------------:|---------:|----------:|-----------:|-----------:|
| No output buffering    |  50 MB             |   97s    |  0.5 MB/s |            |            |
| No output buffering    | 500 MB             | 1130s    |  0.4 MB/s |   3        | 125,000    |
| No output buffering    | 800 MB             | 1809s    |  0.4 MB/s |            |            |
| 8 KiB output buffering |  50 MB             |    5s    | 10.0 MB/s |            |            |
| 1 MiB output buffering |  50 MB             |    5s    | 10.0 MB/s |            |            |
| 8 KiB output buffering | 500 MB             |   52s    |  9.8 MB/s |  15        |   2,100    |
| 8 KiB output buffering | 800 MB             |   80s    | 10.0 MB/s |            |            |
| 1 MiB output buffering | 800 MB             |   82s    |  9.7 MB/s |            |            |


* Average write IO/s over time (estimated via iotop)
** Average number of ca
