## V 2.x.x (NEXT)

* _tbd_

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
