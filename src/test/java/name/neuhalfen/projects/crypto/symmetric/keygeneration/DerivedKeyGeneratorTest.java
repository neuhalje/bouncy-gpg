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

    return new DerivedKeyGenerator(kdf);
  }

  private DerivedKeyGenerator sutDifferentKey() {
    final byte[] MASTERKEY_KEY = new byte[]{9, 8, 7};

    final KeyDerivationFunction kdf = new HKDFSHA256(MASTERKEY_KEY);

    return new DerivedKeyGenerator(kdf);
  }

  @Test
  public void constructDerivedKeyIdentifier_withGivenContext_returnsValidIdentifier()
      throws Exception {
    assertThat("   6:person:47", is(sut().constructDerivedKeyIdentifier("person", "47")));
  }

  @Test
  public void constructDerivedKeyIdentifier_withEmptyContext_returnsValidIdentifier()
      throws Exception {
    assertThat("   0::47", is(sut().constructDerivedKeyIdentifier("", "47")));
  }

  @Test
  public void constructDerivedKeyIdentifier_withColonContext_returnsValidIdentifier()
      throws Exception {
    assertThat("   1:::47", is(sut().constructDerivedKeyIdentifier(":", "47")));
  }

  @Test(expected = IllegalArgumentException.class)
  public void constructDerivedKeyIdentifier_withoutIdentifier_throws() throws Exception {
    sut().constructDerivedKeyIdentifier("I will fail", "");
  }

  @Test
  public void keyDerivation_returnsCorrectKeySize() throws Exception {
    final byte[] key128 = sut().deriveKey(DERIVED_KEY_SALT, "Context", "id", 128);
    final byte[] key256 = sut().deriveKey(DERIVED_KEY_SALT, "Context", "id", 256);
    assertThat(key128.length, equalTo(128 / 8));
    assertThat(key256.length, equalTo(256 / 8));
  }

  @Test
  public void keyDerivation_isDeterministic_withTwoInstances() throws Exception {
    final byte[] key1 = sut().deriveKey(DERIVED_KEY_SALT, "Context", "id", KEY_LEY);
    final byte[] key2 = sut().deriveKey(DERIVED_KEY_SALT, "Context", "id", KEY_LEY);
    assertThat(key1, equalTo(key2));
  }

  @Test
  public void keyDerivation_isDeterministic_withOneInstance() throws Exception {
    final DerivedKeyGenerator sut = sut();

    final byte[] key1 = sut.deriveKey(DERIVED_KEY_SALT, "Context", "id", KEY_LEY);
    final byte[] key2 = sut.deriveKey(DERIVED_KEY_SALT, "Context", "id", KEY_LEY);
    assertThat(key1, equalTo(key2));
  }


  @Test
  public void keyDerivation_differentSecrets_giveDifferentDerivedKeys() throws Exception {
    final byte[] key1 = sut().deriveKey(DERIVED_KEY_SALT, "Context", "id", KEY_LEY);
    final byte[] key2 = sutDifferentKey().deriveKey(DERIVED_KEY_SALT, "Context", "id", KEY_LEY);
    assertThat(key1, not(equalTo(key2)));
  }

  @Test
  public void keyDerivation_differentIDs_giveDifferentDerivedKeys() throws Exception {
    final DerivedKeyGenerator sut = sut();

    final byte[] key1 = sut.deriveKey(DERIVED_KEY_SALT, "Context", "id1", KEY_LEY);
    final byte[] key2 = sut.deriveKey(DERIVED_KEY_SALT, "Context", "id2", KEY_LEY);
    assertThat(key1, not(equalTo(key2)));
  }

  @Test
  public void keyDerivation_differentContext_giveDifferentDerivedKeys() throws Exception {
    final DerivedKeyGenerator sut = sut();

    final byte[] key1 = sut.deriveKey(DERIVED_KEY_SALT, "Context1", "id", KEY_LEY);
    final byte[] key2 = sut.deriveKey(DERIVED_KEY_SALT, "Context2", "id", KEY_LEY);
    assertThat(key1, not(equalTo(key2)));
  }
}