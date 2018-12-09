package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;

import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.KeysTestHelper.assertIsCorrectPublicKey;

import java.io.IOException;
import java.security.Security;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy.PURPOSE;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.junit.Before;
import org.junit.Test;


/**
 * This test complements RFC4880KeySelectionStrategyTest by separating
 * the query string aspect (analog to ByEMailKeySelectionStrategyTest)
 */
public class RFC4880KeySelectionStrategyQueryStringTest {


  final KeyringConfig keyringConfig = RFC4880TestKeyringsDedicatedSigningKey
      .publicAndPrivateKeyKeyringConfig();

  @Before
  public void before() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }


  private KeySelectionStrategy getSut() {
    return new Rfc4880KeySelectionStrategy(
        RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_GUARANTEED_EXPIRED_AT);
  }


  @Test
  public void searchForEMailUnquoted_keyExists_keyIsFound()
      throws IOException, PGPException {

    // searching for a key based on an unquoted (without <..>) email returns the key
    final KeySelectionStrategy sut = getSut();

    assertIsCorrectPublicKey(RFC4880TestKeyringsDedicatedSigningKey.ENCRYPTION_KEY,
        sut.selectPublicKey(PURPOSE.FOR_ENCRYPTION, "rfc4880@example.org", keyringConfig));

    assertIsCorrectPublicKey(RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_ACTIVE,
        sut.selectPublicKey(PURPOSE.FOR_SIGNING, "rfc4880@example.org", keyringConfig));
  }


  @Test
  public void searchForEMailQuoted_keyExists_keyIsFound()
      throws IOException, PGPException {

    // searching for a key based on an quoted (with <..>) email returns the key
    final KeySelectionStrategy sut = getSut();

    assertIsCorrectPublicKey(RFC4880TestKeyringsDedicatedSigningKey.ENCRYPTION_KEY,
        sut.selectPublicKey(PURPOSE.FOR_ENCRYPTION, "<rfc4880@example.org>", keyringConfig));

    assertIsCorrectPublicKey(RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_ACTIVE,
        sut.selectPublicKey(PURPOSE.FOR_SIGNING, "<rfc4880@example.org>", keyringConfig));
  }


  @Test
  public void searchForUserName_keyExists_keyIsNotFound()
      throws IOException, PGPException {

    // only find the email, not by users name
    final KeySelectionStrategy sut = getSut();

    assertIsCorrectPublicKey(RFC4880TestKeyringsDedicatedSigningKey.ENCRYPTION_KEY,
        sut.selectPublicKey(PURPOSE.FOR_ENCRYPTION, "RFC4880 Test User", keyringConfig));

    assertIsCorrectPublicKey(RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_ACTIVE,
        sut.selectPublicKey(PURPOSE.FOR_SIGNING, "RFC4880 Test User", keyringConfig));
  }


}