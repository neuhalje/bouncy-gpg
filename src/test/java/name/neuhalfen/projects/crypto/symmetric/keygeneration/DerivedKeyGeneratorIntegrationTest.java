package name.neuhalfen.projects.crypto.symmetric.keygeneration;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;

import java.security.GeneralSecurityException;
import org.bouncycastle.util.encoders.Hex;
import org.junit.Test;

public class DerivedKeyGeneratorIntegrationTest {


  @Test
  public void derive_works() throws GeneralSecurityException {
    // Rather obviously the master key MUST NOT be part of the source code!
    // This is only for demonstration purposes!
    byte[] masterkey = Hex.decode("81d0994d0aa21b786d6b8dc45fc09f31");

    // The salt value should not be part of the source code.
    // The same salt value can be reused for all key derivations.
    byte[] salt = Hex.decode("b201445d3bcdc7a07c469b7d7ef8988c");

    // These settings depend on the algorithms used.
    // This combination could e.g. be used for AES-256 in CTR or CBC mode
    final int IV_LENGTH_BYTES = 128 / 8;

    // For AES-128 use KEY_LENGTH_BYTES = 128/8
    // This is the length of the generated key.
    // The master key used in this example has a length of 128 bits, yet the generated key is much longer.
    final int KEY_LENGTH_BYTES = 256 / 8;

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

    assertThat(Hex.toHexString(iv), equalTo("f448a884f7b605e6da01d540966e292e"));
    assertThat(Hex.toHexString(key),
        equalTo("551cb7df244e577b5b556634117c38953af706a49e4d9bb09cbdb01bbfc9d8ff"));
  }
}
