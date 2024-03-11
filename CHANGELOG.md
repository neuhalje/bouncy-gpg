## V 2.x.x (NEXT)

* Enh: Upgrade tooling and migrate to GitHub Actions.

## V 2.3.0 Bugfix Release

This releases fixes a security issue (#50) where encrypted, but not signed archives could be modified. 
Some background on MDC and why it's important security-wise: https://gpgtools.tenderapp.com/kb/faq/modification-detection-code-mdc-errors

* Fix: Do not expose logback as compile-time dependency (#41)
* Fix: java.io.EOFException: Unexpected end of ZIP input stream using 2.2.0 version for PGP file (#46)
* Fix: KeyFlag#extractPublicKeyFlags throws NullPointerException if called on an older public key with no hashed subpackets (#48)
* Fix: Encrypting with keys that don't have a KeyFlags subpacket (#50)
* Fix: MDC (integrity checksum) is not verified when decrypting (#45)
* Enh: Bump Bouncy Castle to 1.67


## V 2.2.0 Key generation

* new: Add key generation (initial version by Paul Schaub [@vanitasvitae])
* Fix: Encryption without having any private key.
* Enh: Integration tests with GnuPG
* Enh: Tiger no longer recommended
* Enh: Add algorithm suite for OpenPGP for XMPP (courtesy Paul Schaub)
* Enh: Add 'BouncyGPG.registerProvider()'
* Enh: Merge [Better error messages by user9209](https://github.com/neuhalje/bouncy-gpg/pull/36)
* Enh: Smaller fixes
* Enh: Bump BouncyCastle to 1.64

### API Changes (breaking)

* none

### API Changes (non breaking)

* new: `BouncyGPG.registerProvider()`
* new: key generation via `BouncyGPG.createKeyPair()`
* new: algorithm suite for OpenPGP for XMPP (XEP-0373)
* dep: StreamBasedKeyringConfig, ResourceBasedKeyringConfig, and StreamBasedKeyringConfig deprecated in favor of InMemoryKeyring

## V 2.1.2 OSGI bundle and minor improvements

* Enh: Merge [OSGI support by basdfish69](https://github.com/neuhalje/bouncy-gpg/pull/29)
* Enh: Add support for Java 11
* Enh: SignaturesMissingException carries list of missing signatures
* Doc: Minor documentation improvements
* Tst: Improve test coverage
* Dep: Update test & minor dependencies
* Ref: Refactor argument checking into helper methods



## V 2.1.1 Bugfix release

* Fix: Add support to search for the whole UID instead of e-mail only
* Dep: Bump to BC 1.60
* Doc: Add code of conduct, list of authors

### API Changes

* Loosen restriction to search for e-mail only in `Rfc4880KeySelectionStrategy`.
  Old behaviour in `ByEMailKeySelectionStrategy`

#### Breaking
* _none_ if you only used the builder API (see `ByEMailKeySelectionStrategy`).

## V 2.1.0
* Switch to APACHE2.0 license
* New maven example
* Improved test coverage
* Add Concordion spec-test and tutorial
* Add [website](https://neuhalje.github.io/bouncy-gpg/) generated with [hugo](https://gohugo.io/) (wip)
* Support for key derivation use cases (--> https://github.com/neuhalje/presentation_content-encryption )
* Bump to BC 1.59

### API Changes
#### Breaking
* PGPHashAlgorithms / PGPSymmetricEncryptionAlgorithms  / PGPCompressionAlgorithms: Encapsulate public final fields with getter
* Removed ReencryptExplodedZipMultithreaded
* Selection of keys was not compliant with [RFC 4880](https://tools.ietf.org/html/rfc4880#section-5.2.3.3). _Probably_ this is non-breaking for most users. Use [Pre202KeySelectionStrategy](src/main/java/name/neuhalfen/projects/crypto/bouncycastle/openpgp/keys/callbacks/Pre202KeySelectionStrategy.java) for old behaviour.

#### New
* Encrypt to multiple recipients
* Finer grained control over key selection
* Symmertric key derivation (`name.neuhalfen.projects.crypto.symmetric.keygeneration`) (BETA!!)

## V 2.0.1
* Minor changes in build system

## V 2.0.0
* Create CHANGELOG
* First release with new API

## V 1.x.x
* Initial release(s)
