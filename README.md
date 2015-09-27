build
=======

`./gradlew  shadowJar`

Performance Results
===================

Buffering via `BufferedOutputStream` makes a huge performance impact because it cuts down syscall count approx. by the cache size.

See [Main.java](./src/main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/Main.java):

| Buffering              | source file size   | duration | throughput |
|------------------------|-------------------:|---------:|-----------:|
| No output buffering    |  50 MB             |   97s    |  0.51 MB/s |
| No output buffering    | 800 MB             | 1809s    |  0.44 MB/s |
| 8 KiB output buffering |  50 MB             |    5s    | 10.00 MB/s |
| 1 MiB output buffering |  50 MB             |    5s    | 10.00 MB/s |
| 8 KiB output buffering | 800 MB             |   80s    | 10.00 MB/s |
| 1 MiB output buffering | 800 MB             |   82s    |  9.75 MB/s |
