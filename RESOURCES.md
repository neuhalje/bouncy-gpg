# Additional resources

The documentation of gpg does exist, but is not always readily available. This document
serves as a quick lookup list for interesting resources.

## Keys

* [Anatomy of a GPG Key
](https://davesteele.github.io/gpg/2014/09/20/anatomy-of-a-gpg-key/) - a good explanation of GPG
* [RFC4880 OpenPGP Message Format](http://tools.ietf.org/html/rfc4880)
* The description of gpg output format  is found in the [DETAILS](https://git.gnupg.org/cgi-bin/gitweb.cgi?p=gnupg.git;a=blob_plain;f=doc/DETAILS) file.
* Daniel J. Bernstein and Tanja Lange maintain a list of secure elliptic curves at
 [safecurves.cr.yp.to](https://safecurves.cr.yp.to/).

### Analysing keys

GPG provides tools to debug gpg data (keys, encrypted data, ...)

````text
# cat secretkey.bin|gpg --list-packet

:secret key packet:
	version 4, algo 1, created 1546537076, expires 0
	pkey[0]: [3072 bits]
	pkey[1]: [17 bits]
	skey[2]: [3068 bits]
	skey[3]: [1536 bits]
	skey[4]: [1536 bits]
	skey[5]: [1533 bits]
	checksum: e77b
	keyid: E870CBC56498A13C
# off=1371 ctb=b4 tag=13 hlen=2 plen=35
:user ID packet: "Juliet Capulet <juliet@example.com>"
# off=1408 ctb=89 tag=2 hlen=3 plen=441
:signature packet: algo 1, keyid E870CBC56498A13C
	version 4, created 1546537076, md5len 0, sigclass 0x13
	digest algo 10, begin of digest f9 cb
	hashed subpkt 2 len 4 (sig created 2019-01-03)
	hashed subpkt 27 len 1 (key flags: 03)
	hashed subpkt 22 len 4 (pref-zip-algos: 1 0 3 2)
	hashed subpkt 11 len 8 (pref-sym-algos: 13 2 10 12 9 11 8 7)
	hashed subpkt 21 len 5 (pref-hash-algos: 3 11 9 10 8)
	hashed subpkt 30 len 1 (features: 01)
	subpkt 16 len 8 (issuer key ID E870CBC56498A13C)
	data: [3071 bits]
# off=1852 ctb=9d tag=7 hlen=3 plen=1368
:secret sub key packet:
	version 4, algo 1, created 1546537077, expires 0
	pkey[0]: [3072 bits]
	pkey[1]: [17 bits]
	skey[2]: [3065 bits]
	skey[3]: [1536 bits]
	skey[4]: [1536 bits]
	skey[5]: [1536 bits]
	checksum: ded5
	keyid: 0AA34D4579845F83
# off=3223 ctb=89 tag=2 hlen=3 plen=441
:signature packet: algo 1, keyid E870CBC56498A13C
	version 4, created 1546537077, md5len 0, sigclass 0x18
	digest algo 10, begin of digest 35 d9
	hashed subpkt 2 len 4 (sig created 2019-01-03)
	hashed subpkt 27 len 1 (key flags: 0C)
	hashed subpkt 22 len 4 (pref-zip-algos: 1 0 3 2)
	hashed subpkt 11 len 8 (pref-sym-algos: 13 2 10 12 9 11 8 7)
	hashed subpkt 21 len 5 (pref-hash-algos: 3 11 9 10 8)
	hashed subpkt 30 len 1 (features: 01)
	subpkt 16 len 8 (issuer key ID E870CBC56498A13C)
	data: [3072 bits]
# off=3667 ctb=9d tag=7 hlen=3 plen=1368
:secret sub key packet:
	version 4, algo 1, created 1546537077, expires 0
	pkey[0]: [3072 bits]
	pkey[1]: [17 bits]
	skey[2]: [3067 bits]
	skey[3]: [1536 bits]
	skey[4]: [1536 bits]
	skey[5]: [1534 bits]
	checksum: e29d
	keyid: 9F5497F642F5A3BA
# off=5038 ctb=89 tag=2 hlen=3 plen=441
:signature packet: algo 1, keyid E870CBC56498A13C
	version 4, created 1546537077, md5len 0, sigclass 0x18
	digest algo 10, begin of digest 05 65
	hashed subpkt 2 len 4 (sig created 2019-01-03)
	hashed subpkt 27 len 1 (key flags: 20)
	hashed subpkt 22 len 4 (pref-zip-algos: 1 0 3 2)
	hashed subpkt 11 len 8 (pref-sym-algos: 13 2 10 12 9 11 8 7)
	hashed subpkt 21 len 5 (pref-hash-algos: 3 11 9 10 8)
	hashed subpkt 30 len 1 (features: 01)
	subpkt 16 len 8 (issuer key ID E870CBC56498A13C)
	data: [3068 bits]

````