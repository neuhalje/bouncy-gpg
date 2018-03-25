package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;

import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.Pre202KeySelectionStrategy.extractSecretSigningKeyFromKeyrings;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy.PURPOSE;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.junit.Test;

/**
 * This tests for a BROKEN feature!
 *
 * This tests that the pre-202 implementation and the strategy select the same
 * keys.
 */
public class Pre202KeySelectionStrategyTest {

  @Test
  public void correct_signingKey_isSelected() throws IOException, PGPException {
    final KeyringConfig keyringConfig = RFC4880TestKeyrings.publicKeyOnlyKeyringConfig();

    KeySelectionStrategy sut = new Pre202KeySelectionStrategy();

    PGPPublicKeyRing publicKeyRing = getPgpPublicKeyring(keyringConfig);

    final PGPPublicKey signingPublicKey = sut.selectPublicKey(PURPOSE.FOR_SIGNING, publicKeyRing);

    final long selectedKeyId = signingPublicKey.getKeyID();

    // this is not what the RFC expects but what the pre 202 behaviour is
    assertEquals("It should  select the encryption key",
        RFC4880TestKeyrings.ENCRYPTION_KEY,
        selectedKeyId);

  }

  @Test
  public void oldAndNewImplementation_seelctSameSigningKey() throws IOException, PGPException {
    final KeyringConfig keyringConfig = RFC4880TestKeyrings.publicAndPrivateKeyKeyringConfig();

    final PGPSecretKey pgpSecPre202 =
        extractSecretSigningKeyFromKeyrings(keyringConfig.getSecretKeyRings(),
            RFC4880TestKeyrings.UID_EMAIL);

    KeySelectionStrategy sut = new Pre202KeySelectionStrategy();

    final PGPPublicKey selectedPublicKey = sut
        .selectPublicKey(PURPOSE.FOR_SIGNING, getPgpPublicKeyring(keyringConfig));

    assertEquals("Old and new should select the same private key", pgpSecPre202.getKeyID(),
        selectedPublicKey.getKeyID());

  }

  private PGPPublicKeyRing getPgpPublicKeyring(KeyringConfig keyringConfig)
      throws IOException, PGPException {
    // only one keyring in the example
    return keyringConfig.getPublicKeyRings().getKeyRings().next();
  }

}