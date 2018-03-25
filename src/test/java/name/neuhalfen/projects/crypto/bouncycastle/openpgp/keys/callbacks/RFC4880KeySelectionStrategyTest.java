package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;

import java.io.IOException;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.PGPUtilities;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.junit.Test;


/**
 * Test for compliance with https://tools.ietf.org/html/rfc4880#section-5.2.3.3
 * when selecting keys.
 */
public class RFC4880KeySelectionStrategyTest {

  @Test
  public void correct_signingKey_isSelected() throws IOException, PGPException {
    final KeyringConfig keyringConfig = RFC4880TestKeyrings.publicKeyOnlyKeyringConfig();
    final PGPPublicKeyRingCollection publicKeyRings = keyringConfig.getPublicKeyRings();

    // only one keyring in the example
    PGPPublicKeyRing publicKeyRing = publicKeyRings.getKeyRings().next();

    final PGPPublicKey signingPublicKey = PGPUtilities
        .extractSigningPublicKey(publicKeyRing);

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


    assertEquals("It should select the correct signingkey",
        RFC4880TestKeyrings.SIGNATURE_KEY_ACTIVE,
        selectedKeyId);
  }
}