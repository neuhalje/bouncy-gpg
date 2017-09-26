{
"title" : "Key generation and derivation",
"description": "Cryptographic keys are the input parameters to many cryptographic operations, namely en-/decryption and signatures. This HOWTO will show you how to create keys from passwords, and how to derive multiple keys from one master key.",
"tags" : [
    "howto",
    "key derivation", "TODO"
],
"categories" : [
    "keys"
]
}

Cryptographic keys are the input parameters to many cryptographic operations, namely en-/decryption and signatures. This HOWTO will show you how to create keys from passwords, and how to derive multiple keys from one master key.

Cryptographic keys can be obtained by two methods:

* by generating a key from random data (e.g. `SecureRandom`)
* by deriving the key from other data (_input key material_)

## Key Generation
TODO

## Key Derivation

The words _password_ and _cryptographic key_ are often used interchangeably, although they are technically quite different.

A _password_ is a sequence of characters of often arbitrary length. A _cryptographic key_ is a binary object that has an algorithm specific structure to it.

* Keys can be derived from passwords with [password based key derivation functions](passwords/).
* Key  can be derived from other keys with [key derivation functions](kdf/).



## Further Reading
* [Key stretching](https://en.wikipedia.org/wiki/Key_stretching) on Wikipedia.
* [NIST Special Publication 800-132: Recommendation for Password-Based Key Derivation](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
* [Key derivation function](https://en.wikipedia.org/wiki/Key_derivation_function) on Wikipedia.
