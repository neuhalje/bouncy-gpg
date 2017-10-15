## V 2.0.2 (NEXT)
* Switch to APACHE2.0 license
* New maven example
* Improved test coverage
* Add Concordion spec-test and tutorial
* Add [website](https://neuhalje.github.io/bouncy-gpg/) generated with [hugo](https://gohugo.io/)
* Support for key derivation use cases (--> https://github.com/neuhalje/presentation_content-encryption )
* Bump to BC 1.58

### API Changes
#### Breaking
* PGPHashAlgorithms / PGPSymmetricEncryptionAlgorithms  / PGPCompressionAlgorithms: Encapsulate public final fields with getter
* Removed ReencryptExplodedZipMultithreaded
#### New
* Symmertric key derivation (`name.neuhalfen.projects.crypto.symmetric.keygeneration`)

## V 2.0.1
* Minor changes in build system

## V 2.0.0
* Create CHANGELOG
* First release with new API

## V 1.x.x
* Initial release(s)
