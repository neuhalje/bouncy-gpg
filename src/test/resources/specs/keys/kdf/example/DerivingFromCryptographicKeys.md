{
"title" : "Example: Deriving record specific keys",
"description": "Deriving record specific keys with HKDF.",
"tags" : [
    "howto",
    "key derivation",
    "example"
],
"categories" : [
    "keys"
]
}

_The following code snippets are actually compiled and run during the BouncyGPG build process. This ensures that all examples are correct._


To derive another key from one (master key) a key derivation function should be used. _HKDF_  defined in [RFC5869](https://tools.ietf.org/html/rfc5869) is such a function.

Internally HKDF uses an [HMAC](https://tools.ietf.org/html/rfc2104) to derive multiple keys fro one master key.

To quote from [RFC5869](https://tools.ietf.org/html/rfc5869):

> A key derivation function (KDF) is a basic and essential component of
> cryptographic systems.  Its goal is to take some source of initial
> keying material and derive from it one or more cryptographically
> strong secret keys.
   
The following code will derive an AES-128 key and IV (or nonce) for a record identified as version `3` of row #`2386221` in `MY_TABLE`:

    ```groovy result:#deriveKey
    import java.security.GeneralSecurityException;
    import name.neuhalfen.projects.crypto.symmetric.keygeneration.DerivedKeyGenerator;
    import name.neuhalfen.projects.crypto.symmetric.keygeneration.DerivedKeyGeneratorFactory;
    import org.bouncycastle.util.encoders.Hex;
    
    // Rather obviously the master key MUST NOT be part of the source code!
    // This is only for demonstration purposes!
    byte[] masterkey = Hex.decode("81d0994d0aa21b786d6b8dc45fc09f31");
    
    // The salt value should not be part of the source code.
    // The same salt value can be reused for all key derivations.
    byte[] salt = Hex.decode("b201445d3bcdc7a07c469b7d7ef8988c");
    
    // These settings depend on the algorithms used.
    // This combination could e.g. be used for AES-256 in CTR or CBC mode
    final int IV_LENGTH_BYTES = 128 / 8;
    
    // This is the length of the generated key.
    // For AES-256 use KEY_LENGTH_BYTES = 256/8
    final int KEY_LENGTH_BYTES = 128 / 8;
    
    // The key to be generated depends on three things:
    //  -  the master key
    //  -  the salt value
    //  -  the info
    // Master key and salt are relatively static and are often scoped "per installation of the application".
    //
    // The info value must(!) uniquely(!) identify the object to be encrypted.
    // It is mandatory that the same key/iv combination is not used multiple times.
    // A good way to do this is to use a combination of the objects type, id, and version.
    // Version means: "This is incremented every time the record is changed".
    // Using a random value (that is refreshed for each update) is also possible.
    String context = "MY_TABLE";
    String databasePrimaryKey = "2386221";
    String recordVersion = "3";
    
    final DerivedKeyGenerator derivedKeyGenerator =
       DerivedKeyGeneratorFactory
           .fromInputKey(masterkey)
           .andSalt(salt)
           .withHKDFsha256();
    
    final byte[] iv = new byte[IV_LENGTH_BYTES];
    final byte[] key = new byte[KEY_LENGTH_BYTES];
    
    // The key derivation creates (arbitrary long) streams of "randomness" (it is a PRF - pseudo random function).
    // Request enough randomness to cover IV and key
    final byte[] keyAndIV = derivedKeyGenerator
       .deriveKey(context, databasePrimaryKey, recordVersion, IV_LENGTH_BYTES + KEY_LENGTH_BYTES);
    
    System.arraycopy(keyAndIV, 0, key, 0, key.length);
    System.arraycopy(keyAndIV, key.length, iv, 0, iv.length);
    
    System.out.println("IV:  " + Hex.toHexString(iv));
    System.out.println("Key: " + Hex.toHexString(key));
    ```
  

    
#### [Example: Changing the version will change the derived key](- "Changing the version will change the derived key")

Changing the version of the record value will derive different keys. The IV for this example is not shown. Also the key length is set to 128 bit.

| [deriveKey][][Context][contextId] | [ID][idUniqueInContext]                  | [Version][recordVersion]             | [derived key][derivedKey]            |  Remark |
|-----------------------------------|------------------------------------------|--------------------------------------|--------------------------------------|---------|
| MY_TABLE                          | 2386221                                  | 1                                    |  0xec82fb52017238960175d3a67d8f8f97  | _This and the following two rows show keys for multiple versions of the same record._ |
| MY_TABLE                          | 2386221                                  | **2**                                |  0xe1ba165e7796a4eae010ba90831d00c5  | _Incrementing the version field will generate different keys._ |
| MY_TABLE                          | 2386221                                  | **3**                                |  0x551cb7df244e577b5b556634117c3895  | _The example shown above._ |
| **CarInsuranceContract**          | 2386221                                  | 3                                    |  0x8cf4a7e699f51ad9fa01598898f02052  | _The same 'row' in different 'tables' yields different keys._ |
| CarInsuranceContract              | **D9FF7A8A-5692-48D7-A4F7-45E149448BBA** | 3                                    |  0xb2381876a3b63a1e90f35f8880c6373b  | _IDs just need to be distinct, not necessarily integers._ | 
| CarInsuranceContract              | D9FF7A8A-5692-48D7-A4F7-45E149448BBA | **9EBDF712-BBBE-480E-8369-A79F8E653B63** |  0x7eed3ff1996d95db97eefcbd55f2d8d3  | _Versions just need to be distinct, not necessarily integers._ | 
| CarInsuranceContract              | D9FF7A8A-5692-48D7-A4F7-45E149448BBA | **570E7AA2-EC6A-4F14-A58E-BB3E7E671FED** |  0x2e7bc71432f52b1a868553de401c4f84  | |

[contextId]: - "#contextId"
[idUniqueInContext]: - "#idUniqueInContext"
[recordVersion]: - "#recordVersion"
[deriveKey]: - "#key = deriveKey(#contextId, #idUniqueInContext, #recordVersion)"
[derivedKey]: - "?=#key.derivedKey"
