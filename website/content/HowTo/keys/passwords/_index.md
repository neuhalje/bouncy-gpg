{
"title" : "From password to key",
"tags" : [
    "howto",
    "key derivation",
    "passwords",
    "TODO"
],
"categories" : [
    "keys"
]
}

The words _password_ and _cryptographic key_ are often used interchangeably, although they are technically very different.
Most systems use passwords to _derive_ cryptographic keys, e.g. the password entered to decrypt a ZIP file is used to derive  a cryptographic key, which then is used to en-/decrypt the ZIP file.

The process of deriving  a cryptographic key from a password is called _password based key derivation_. Because passwords are often to short/predictable this derivation often also implements some kind of _key strengthening_ or _key stretching_ (see below for more info).

{{<mermaid align="left">}}
graph LR;
    P(Password) --> KDF[Key Derivation Function]
    S(Salt) --> KDF
    KDF --> K(Key)
    K -.-> AES[AES]
{{< /mermaid >}}

To properly derive a key from a passwords a few aspects are important to consider. 


{{% panel theme="success" header="TL;RD: Recommendation" %}}

*Recommendation*:

* Always use a key derivation function. _Never_ use input key material without a key derivation function.
* Use long and complex passwords as key source (128 bit key => 22 characters, 256 bit keys => 44 characters!)
* Use a random salt value that is as long as the key (128 or 256 bits)
* Configure the key stretching to be as slow (sic!) as possible 
{{% /panel %}}

Cryptographic key derivation functions should be used to derive a key from a password (or _any_ other source material).
Bouncy-GPG uses [SCrypt](https://en.wikipedia.org/wiki/Scrypt)  for key stretching.

## Requirements for key derivation

For those interested in learning a bit of background about key derivation the following paragraphs give a very short overview of the basic requirements of key derivation (from a password).

These are not all requirements for key derivation functions. The requirements shown here shed some light on key derivation  functions from an _API user_ perspective.

### Deterministic

The process of key derivation has to be [deterministic](https://en.wikipedia.org/wiki/Deterministic_system). That is, given the same input parameters (password and other parameters of the _derivation function_) the generated key is always the same.

### Password length
Cryptographically strong passwords are remarkably difficult to use because they are really, really long.
For the sake of discussion assume a password with the allowed symbols `a-z + A-Z + 0-9`. That are 62 different symbols per character. This is a bit less than ~6 bit per character.

A cryptographic key typically has a length of 128 or 256 completely random bits. E.g. a secure 128 bit key would require a completely random password of 22 characters (precisely `128 / log_2(62)` [*]). Sometimes this cannot be ensured, for example when the password is a users login password.

To derive keys from passwords two length-related problems need to be solved:

1. Squash arbitrary long passwords into 128 / 256 bit keys
2. Prevent attackers from enumerating (to short) passwords

[*] _Rule of thumb: `c` possible symbols are `log_2(c)` bits per character. `n` characters are then `n * log_2(c)` bits.  If your calculator does not have `log_2` use `num_bits ~= n * 3.3 * log_10(c)`_

## Prevent pre-computation with salt

Especially for short passwords it is desirable to prevent attackers from pre-computing (e.g. with [Rainbow tables](https://en.wikipedia.org/wiki/Rainbow_table))
all possible keys upfront.

There are two strategies to achieve this.

First the calculation can include an additional parameter that makes key derivation specific to an application/installation.
This raises the bar for the attacker because the pre-computation for one application cannot be used for a second application.
Such a value is called a [salt](https://en.wikipedia.org/wiki/Salt_%28cryptography%29) and can be public.

Adding a salt value often is not enough. Even with [consumer hardware](http://cynosureprime.blogspot.de/2017/08/320-million-hashes-exposed.html) simple hashes like SHA-1 or SHA-256 can be calculated at rates of _mega hashes per second_.

Secondly, computation can be made very expensive, so that an attacker would need to spend to much time to compute all possible keys.
This approach is implemented by functions such as  [SCrypt](https://en.wikipedia.org/wiki/Scrypt) or [PBKDF2](https://tools.ietf.org/html/rfc2898).
Slowing down computations is especially important for cases where the attacker has access to the database with the password hashes (and the salt). This is not unlikely because databases are stolen quite frequently.
Brute force protection makes key generation much slower, thus hampering an attacker to just try out every possible user password to "brute force" the key.

Changing the salt value will derive different keys from the same password (thus making  precomputing infeasible).

## Unwanted structure / lacking entropy

Besides the length of the password, it also has a lot of inherent structure (e.g. the mentioned 62 symbols all have the most significant bit set to zero). This structure needs to be "smoothed out" before using the password das key material.

## Further Reading
* [Key stretching](https://en.wikipedia.org/wiki/Key_stretching) on Wikipedia.
* [NIST Special Publication 800-132: Recommendation for Password-Based Key Derivation](http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-132.pdf)
* [Key derivation function](https://en.wikipedia.org/wiki/Key_derivation_function) on Wikipedia.
