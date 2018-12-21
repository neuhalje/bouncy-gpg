package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;

import static junit.framework.TestCase.assertFalse;
import static junit.framework.TestCase.assertTrue;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.security.Security;
import java.time.Instant;
import java.util.Set;
import java.util.stream.Collectors;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy.PURPOSE;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;


/**
 * Test for compliance with https://tools.ietf.org/html/rfc4880#section-5.2.3.3
 * when selecting keys.
 */
@RunWith(Parameterized.class)
public class RFC4880KeySelectionStrategyTest {

  @Parameterized.Parameter
  public /* NOT private */ Class<? extends Rfc4880KeySelectionStrategy> strategyUnderTest;

  /*
   * make sure that all Rfc4880KeySelectionStrategies work as expected
   */
  @Parameterized.Parameters(name = "{0}")
  public static Object[] data() {
    return new Object[]{
        Rfc4880KeySelectionStrategy.class,
        ByEMailKeySelectionStrategy.class};
  }

  Rfc4880KeySelectionStrategy buildSut(final Instant dateOfTimestampVerification) {
    assert strategyUnderTest != null;
    try {
      final Constructor<? extends Rfc4880KeySelectionStrategy> constructor = strategyUnderTest
          .getConstructor(Instant.class);
      return constructor.newInstance(dateOfTimestampVerification);
    } catch (Exception e) {
      throw new AssertionError(
          "Could not create " + strategyUnderTest.getCanonicalName() + " with timestamp");
    }
  }

  @Before
  public void before() {
    BouncyGPG.registerProvider();
  }

  @Test
  public void expiryDetectionWorks_forKeys_withoutExpirationDate()
      throws IOException, PGPException {

    final Rfc4880KeySelectionStrategy sut = buildSut(
        RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_GUARANTEED_EXPIRED_AT);
    final KeyringConfig keyringConfig = RFC4880TestKeyringsDedicatedSigningKey
        .publicKeyOnlyKeyringConfig();

    final PGPPublicKey nonExpiredKey = keyringConfig.getPublicKeyRings()
        .getPublicKey(RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_ACTIVE);
    assertFalse("Key without expiration is not expired", sut.isExpired(nonExpiredKey));
  }

  @Test
  public void expiryDetectionWorks_withExpirationDate_beforeExpiration()
      throws IOException, PGPException {

    final Rfc4880KeySelectionStrategy sut = buildSut(
        RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_GUARANTEED_VALID_AT);

    final KeyringConfig keyringConfig = RFC4880TestKeyringsDedicatedSigningKey
        .publicKeyOnlyKeyringConfig();

    final PGPPublicKey nonExpiredKey = keyringConfig.getPublicKeyRings()
        .getPublicKey(RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_EXPIRED);

    assertFalse("Expiring key is not expired before expiration date", sut.isExpired(nonExpiredKey));
  }


  @Test
  public void expiryDetectionWorks_withExpirationDate_afterExpiration()
      throws IOException, PGPException {

    final Rfc4880KeySelectionStrategy sut = buildSut(
        RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_GUARANTEED_EXPIRED_AT);

    final KeyringConfig keyringConfig = RFC4880TestKeyringsDedicatedSigningKey
        .publicKeyOnlyKeyringConfig();

    final PGPPublicKey expiredKey = keyringConfig.getPublicKeyRings()
        .getPublicKey(RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_EXPIRED);

    assertTrue("Expired key is expired after expiration date", sut.isExpired(expiredKey));
  }

  @Test
  public void revocationDetectionWorks() throws IOException, PGPException {

    final Rfc4880KeySelectionStrategy sut = buildSut(
        RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_GUARANTEED_EXPIRED_AT);

    final KeyringConfig keyringConfig = RFC4880TestKeyringsDedicatedSigningKey
        .publicKeyOnlyKeyringConfig();

    final PGPPublicKey revokedKey = keyringConfig.getPublicKeyRings()
        .getPublicKey(RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_REVOKED);

    assertTrue("Revoked key is expired", sut.isRevoked(revokedKey));

    final PGPPublicKey nonRevokedKey = keyringConfig.getPublicKeyRings()
        .getPublicKey(RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_ACTIVE);
    assertFalse("Non-revoked key  is not revoked", sut.isRevoked(nonRevokedKey));
  }

  @Test
  public void findsPublicKeysForValidation() throws PGPException, IOException {
    final KeySelectionStrategy sut = buildSut(
        RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_GUARANTEED_EXPIRED_AT);

    final KeyringConfig keyringConfig = Configs.keyringConfigFromResourceForRecipient();

    final Set<PGPPublicKey> validPubKeys = sut
        .validPublicKeysForVerifyingSignatures("sender@example.com", keyringConfig);

    assertNotNull("Must never return null", validPubKeys);
    assertEquals("There is a master and a subkey for 'sender@example.com'", 2,
        validPubKeys.size());

    final Set<Long> foundKeyIds = validPubKeys.stream().map(key -> key.getKeyID())
        .collect(Collectors.toSet());

    assertTrue("The correct key has been found",
        foundKeyIds.contains(ExampleMessages.KEY_ID_SENDER));
  }

  @Test()
  public void noPrivateKeys_noSigningKey_isSelected() throws IOException, PGPException {
    final KeyringConfig keyringConfig = RFC4880TestKeyringsDedicatedSigningKey
        .publicKeyOnlyKeyringConfig();

    final KeySelectionStrategy keySelectionStrategy = buildSut(
        RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_GUARANTEED_EXPIRED_AT);

    final PGPPublicKey signingPublicKey = keySelectionStrategy
        .selectPublicKey(PURPOSE.FOR_SIGNING, RFC4880TestKeyringsDedicatedSigningKey.UID_EMAIL,
            keyringConfig);

    assertNull("It should not select a signing key without private key", signingPublicKey);

  }


  @Test()
  public void selectSigningKey_beforeLastKeyExpires_lastValidSigningKeySelected()
      throws IOException, PGPException {
    // rfc4880 hints in 5.2.3.3.  Notes on Self-Signatures
    // "An implementation that encounters multiple self-signatures on the
    // same object may resolve the ambiguity in any way it sees fit, but it
    // is RECOMMENDED that priority be given to the most recent self-
    //  signature."
    final KeyringConfig keyringConfig = RFC4880TestKeyringsDedicatedSigningKey
        .publicAndPrivateKeyKeyringConfig();

    final KeySelectionStrategy keySelectionStrategy = buildSut(
        RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_GUARANTEED_VALID_AT);

    final PGPPublicKey signingPublicKey = keySelectionStrategy
        .selectPublicKey(PURPOSE.FOR_SIGNING, RFC4880TestKeyringsDedicatedSigningKey.UID_EMAIL,
            keyringConfig);

    assertNotNull("It should select a signing key", signingPublicKey);

    final long selectedKeyId = signingPublicKey.getKeyID();

    assertEquals("It should select the last valid key in the list",
        RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_EXPIRED,
        selectedKeyId);

  }

  @Test()
  public void selectSigningKey_afterLastKeyExpires_lastValidSigningKeySelected()
      throws IOException, PGPException {
    // rfc4880 hints in 5.2.3.3.  Notes on Self-Signatures
    // "An implementation that encounters multiple self-signatures on the
    // same object may resolve the ambiguity in any way it sees fit, but it
    // is RECOMMENDED that priority be given to the most recent self-
    //  signature."
    final KeyringConfig keyringConfig = RFC4880TestKeyringsDedicatedSigningKey
        .publicAndPrivateKeyKeyringConfig();

    final KeySelectionStrategy keySelectionStrategy = buildSut(
        RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_GUARANTEED_EXPIRED_AT);

    final PGPPublicKey signingPublicKey = keySelectionStrategy
        .selectPublicKey(PURPOSE.FOR_SIGNING, RFC4880TestKeyringsDedicatedSigningKey.UID_EMAIL,
            keyringConfig);

    assertNotNull("It should select a signing key", signingPublicKey);

    final long selectedKeyId = signingPublicKey.getKeyID();

    assertEquals("It should select the last valid key in the list",
        RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_ACTIVE,
        selectedKeyId);
  }


  @Test()
  public void dedicatedSigningKeys_selectSigningKey_DedicatedKeyisSelected()
      throws IOException, PGPException {
    final KeyringConfig keyringConfig = RFC4880TestKeyringsDedicatedSigningKey
        .publicAndPrivateKeyKeyringConfig();

    final KeySelectionStrategy keySelectionStrategy = buildSut(
        RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_GUARANTEED_EXPIRED_AT);

    final PGPPublicKey signingPublicKey = keySelectionStrategy
        .selectPublicKey(PURPOSE.FOR_SIGNING, RFC4880TestKeyringsDedicatedSigningKey.UID_EMAIL,
            keyringConfig);

    assertNotNull("It should select a signing key", signingPublicKey);

    final long selectedKeyId = signingPublicKey.getKeyID();

    assertNotEquals("It should not select the master key",
        RFC4880TestKeyringsDedicatedSigningKey.MASTER_KEY_ID,
        selectedKeyId);

    assertNotEquals("It should not select the authentication key",
        RFC4880TestKeyringsDedicatedSigningKey.AUTHENTICATION_KEY,
        selectedKeyId);

    assertNotEquals("It should not select the encryption key",
        RFC4880TestKeyringsDedicatedSigningKey.ENCRYPTION_KEY,
        selectedKeyId);

    assertNotEquals("It should not select the revoked key",
        RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_REVOKED,
        selectedKeyId);

    assertNotEquals("It should not select the expired key",
        RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_EXPIRED,
        selectedKeyId);

    assertEquals("It should select the correct signing key",
        RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_ACTIVE,
        selectedKeyId);
  }


  @Test()
  public void masterIsSigningKey_selectSigningKey_MasterKeyIsSelected()
      throws IOException, PGPException {
    final KeyringConfig keyringConfig = RFC4880TestKeyringsMasterKeyAsSigningKey
        .publicAndPrivateKeyKeyringConfig();

    final KeySelectionStrategy keySelectionStrategy = buildSut(Instant.MAX);

    final PGPPublicKey signingPublicKey = keySelectionStrategy
        .selectPublicKey(PURPOSE.FOR_SIGNING, RFC4880TestKeyringsMasterKeyAsSigningKey.UID_EMAIL,
            keyringConfig);

    assertNotNull("It should select a signing key", signingPublicKey);

    final long selectedKeyId = signingPublicKey.getKeyID();

    assertEquals("It should  select the master key",
        RFC4880TestKeyringsMasterKeyAsSigningKey.MASTER_KEY_ID,
        selectedKeyId);
  }
}