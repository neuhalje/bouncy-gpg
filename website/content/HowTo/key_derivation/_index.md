{
"title" : "Key derivation",
"tags" : [
    "howto",
    "key derivation"
],
"categories" : [
    "keys"
]
}

The words _password_ and _cryptographic key_ are often used interchangeably, although they are technically very different.

A _password_ is a sequence of characters of often arbitrary length. A _cryptographic key_ is a binary object that often has an algorithm specific structure to it.

## TL;RD: Recommendation
* Always use a key derivation function. _Never_ use input key material without a key derivation function.
* Use a random salt value that is as long as the key (128 or 256 bits)
* Configure the key derivation to be as slow (sic!) as possible 


## Further Reading
* [Key stretching](https://en.wikipedia.org/wiki/Key_stretching) on Wikipedia.
* [NIST Special Publication 800-132: Recommendation for Password-Based Key Derivation](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
* [Key derivation function](https://en.wikipedia.org/wiki/Key_derivation_function) on Wikipedia.
