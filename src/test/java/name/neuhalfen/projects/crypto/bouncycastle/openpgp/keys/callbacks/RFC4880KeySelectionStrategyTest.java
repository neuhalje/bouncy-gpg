package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;

import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.util.Set;
import java.util.stream.Collector;
import java.util.stream.Collectors;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy.PURPOSE;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.junit.Test;


/**
 * Test for compliance with https://tools.ietf.org/html/rfc4880#section-5.2.3.3
 * when selecting keys.
 */
public class RFC4880KeySelectionStrategyTest {


  @Test
  public void findsPublicKeysForValidation() throws PGPException, IOException {
    final KeySelectionStrategy sut = new Rfc4880KeySelectionStrategy(
        RFC4880TestKeyrings.SIGNATURE_KEY_GUARANTEED_EXPIRED_AT);

    final KeyringConfig keyringConfig = Configs.keyringConfigFromResourceForRecipient();

    final Set<PGPPublicKey> validPubKeys = sut
        .validPublicKeysForVerifyingSignatures("sender@example.com", keyringConfig);

    assertNotNull("Must never return null", validPubKeys);
    assertEquals("There is a master and a subkey for 'sender@example.com'", 2,
        validPubKeys.size());

    final Set<Long> foundKeyIds = validPubKeys.stream().map(key -> key.getKeyID())
        .collect(Collectors.toSet());

    assertTrue("The correct key has been found", foundKeyIds.contains(ExampleMessages.KEY_ID_SENDER));
  }

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