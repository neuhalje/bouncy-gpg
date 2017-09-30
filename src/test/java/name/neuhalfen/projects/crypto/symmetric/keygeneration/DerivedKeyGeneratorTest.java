package name.neuhalfen.projects.crypto.symmetric.keygeneration;

import static org.hamcrest.Matchers.is;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertThat;

import name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.derivation.HKDFSHA256;
import name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.derivation.KeyDerivationFunction;
import org.junit.Test;


public class DerivedKeyGeneratorTest {

  private final static int KEY_LEY = 128;
  private final static byte[] DERIVED_KEY_SALT = new byte[]{1, 2, 3, 4};

  private DerivedKeyGenerator sut() {
    final byte[] MASTERKEY_KEY = new byte[]{5, 6, 7};

    final KeyDerivationFunction kdf = new HKDFSHA256(MASTERKEY_KEY);

    return new DerivedKeyGenerator(kdf, DERIVED_KEY_SALT);
  }

  private DerivedKeyGenerator sutDifferentKey() {
    final byte[] MASTERKEY_KEY = new byte[]{9, 8, 7};

    final KeyDerivationFunction kdf = new HKDFSHA256(MASTERKEY_KEY);

    return new DerivedKeyGenerator(kdf, DERIVED_KEY_SALT);
  }

  @Test
  public void constructDerivedKeyIdentifier_withGivenContext_returnsValidIdentifier()
      throws Exception {
    assertThat(sut().constructDerivedKeyIdentifier("person", "47", "1"),
        is("0006:person:0002:47:0001:1"));
  }

  @Test
  public void constructDerivedKeyIdentifier_withEmptyContext_returnsValidIdentifier()
      throws Exception {
    assertThat(sut().constructDerivedKeyIdentifier("", "47", "1"), is("0000::0002:47:0001:1"))
    ;
  }

  @Test
  public void constructDerivedKeyIdentifier_withColonContext_returnsValidIdentifier()
      throws Exception {
    assertThat(sut().constructDerivedKeyIdentifier(":", "47", "1"), is("0001:::0002:47:0001:1"));
  }

  @Test(expected = IllegalArgumentException.class)
  public void constructDerivedKeyIdentifier_withoutIdentifier_throws() throws Exception {
    sut().constructDerivedKeyIdentifier("I will fail", "", "1");
  }


  @Test(expected = IllegalArgumentException.class)
  public void constructDerivedKeyIdentifier_withoutVersion_throws() throws Exception {
    sut().constructDerivedKeyIdentifier("I will fail", "4711", "");
  }

  @Test
  public void keyDerivation_returnsCorrectKeySize() throws Exception {
    final byte[] key128 = sut().deriveKey("Context", "id", "1", 128 / 8);
    final byte[] key256 = sut().deriveKey("Context", "id", "1", 256 / 8);
    assertThat(key128.length, equalTo(128 / 8));
    assertThat(key256.length, equalTo(256 / 8));
  }

  @Test
  public void keyDerivation_isDeterministic_withTwoInstances() throws Exception {
    final byte[] key1 = sut().deriveKey("Context", "id", "1", KEY_LEY);
    final byte[] key2 = sut().deriveKey("Context", "id", "1", KEY_LEY);
    assertThat(key1, equalTo(key2));
  }

  @Test
  public void keyDerivation_isDeterministic_withOneInstance() throws Exception {
    final DerivedKeyGenerator sut = sut();

    final byte[] key1 = sut.deriveKey("Context", "id", "1", KEY_LEY);
    final byte[] key2 = sut.deriveKey("Context", "id", "1", KEY_LEY);
    assertThat(key1, equalTo(key2));
  }


  @Test
  public void keyDerivation_differentSecrets_giveDifferentDerivedKeys() throws Exception {
    final byte[] key1 = sut().deriveKey("Context", "id", "1", KEY_LEY);
    final byte[] key2 = sutDifferentKey().deriveKey("Context", "id", "1", KEY_LEY);
    assertThat(key1, not(equalTo(key2)));
  }

  @Test
  public void keyDerivation_differentIDs_giveDifferentDerivedKeys() throws Exception {
    final DerivedKeyGenerator sut = sut();

    final byte[] key1 = sut.deriveKey("Context", "id1", "1", KEY_LEY);
    final byte[] key2 = sut.deriveKey("Context", "id2", "1", KEY_LEY);
    assertThat(key1, not(equalTo(key2)));
  }

  @Test
  public void keyDerivation_differentContext_giveDifferentDerivedKeys() throws Exception {
    final DerivedKeyGenerator sut = sut();

    final byte[] key1 = sut.deriveKey("Context1", "id", "1", KEY_LEY);
    final byte[] key2 = sut.deriveKey("Context2", "id", "1", KEY_LEY);
    assertThat(key1, not(equalTo(key2)));
  }

  @Test
  public void keyDerivation_differentVersions_giveDifferentDerivedKeys() throws Exception {
    final DerivedKeyGenerator sut = sut();

    final byte[] key1 = sut.deriveKey("Context", "id", "1", KEY_LEY);
    final byte[] key2 = sut.deriveKey("Context", "id", "2", KEY_LEY);
    assertThat(key1, not(equalTo(key2)));
  }
}