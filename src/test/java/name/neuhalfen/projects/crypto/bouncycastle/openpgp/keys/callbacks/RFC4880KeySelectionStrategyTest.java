package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy.PURPOSE;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.junit.Test;


/**
 * Test for compliance with https://tools.ietf.org/html/rfc4880#section-5.2.3.3
 * when selecting keys.
 */
public class RFC4880KeySelectionStrategyTest {


  @Test()
  public void noPrivateKeys_noSigningKey_isSelected() throws IOException, PGPException {
    final KeyringConfig keyringConfig = RFC4880TestKeyrings.publicKeyOnlyKeyringConfig();

    final KeySelectionStrategy keySelectionStrategy = new Rfc4880KeySelectionStrategy(
        RFC4880TestKeyrings.SIGNATURE_KEY_GUARANTEED_EXPIRED_AT);

    final PGPPublicKey signingPublicKey = keySelectionStrategy
        .selectPublicKey(PURPOSE.FOR_SIGNING, RFC4880TestKeyrings.UID_EMAIL, keyringConfig);

    assertNull("It should not select a signing key without private key", signingPublicKey);

  }


  @Test()
  public void correct_signingKey_isSelected() throws IOException, PGPException {
    final KeyringConfig keyringConfig = RFC4880TestKeyrings.publicAndPrivateKeyKeyringConfig();

    final KeySelectionStrategy keySelectionStrategy = new Rfc4880KeySelectionStrategy(
        RFC4880TestKeyrings.SIGNATURE_KEY_GUARANTEED_EXPIRED_AT);

    final PGPPublicKey signingPublicKey = keySelectionStrategy
        .selectPublicKey(PURPOSE.FOR_SIGNING, RFC4880TestKeyrings.UID_EMAIL, keyringConfig);

    assertNotNull("It should select a signing key", signingPublicKey);

    final long selectedKeyId = signingPublicKey.getKeyID();

    assertNotEquals("It should not select the master key", RFC4880TestKeyrings.MASTER_KEY_ID,
        selectedKeyId);

    assertNotEquals("It should not select the authentication key",
        RFC4880TestKeyrings.AUTHENTICATION_KEY,
        selectedKeyId);

    assertNotEquals("It should not select the encryption key",
        RFC4880TestKeyrings.ENCRYPTION_KEY,
        selectedKeyId);

    assertNotEquals("It should not select the revoked key",
        RFC4880TestKeyrings.SIGNATURE_KEY_REVOKED,
        selectedKeyId);

    assertNotEquals("It should not select the expired key",
        RFC4880TestKeyrings.SIGNATURE_KEY_EXPIRED,
        selectedKeyId);

    assertEquals("It should select the correct signing key",
        RFC4880TestKeyrings.SIGNATURE_KEY_ACTIVE,
        selectedKeyId);
  }
}