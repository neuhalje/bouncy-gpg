package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;

import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.RFC4880TestKeyringsDedicatedSigningKey.EXPIRED_KEY_CREATION_TIME;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.security.Security;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.junit.Before;
import org.junit.Test;


/**
 * Sanity test for the rfc4880  test keyrings.
 */
public class RFC4880TestKeyringsDedicatedSigningKeySanityTest {

  @Before
  public void before() {
    BouncyGPG.registerProvider();
  }

  @Test
  public void publicKeys_containsOnlyOneCollection() throws IOException, PGPException {
    final KeyringConfig sut = RFC4880TestKeyringsDedicatedSigningKey.publicKeyOnlyKeyringConfig();
    assertEquals("Only one public keyring in the sut", 1, sut.getPublicKeyRings().size());
  }

  @Test
  public void privateKeys_containsOnlyOneCollection() throws IOException, PGPException {
    final KeyringConfig sut = RFC4880TestKeyringsDedicatedSigningKey
        .publicAndPrivateKeyKeyringConfig();
    assertEquals("Only one private keyring in the sut", 1, sut.getSecretKeyRings().size());
  }

  @Test
  public void validate_pubKeyOnly_TestSetup() throws IOException, PGPException {
    final KeyringConfig sut = RFC4880TestKeyringsDedicatedSigningKey.publicKeyOnlyKeyringConfig();

    assertFalse("Master private key does not exist",
        sut.getSecretKeyRings().contains(RFC4880TestKeyringsDedicatedSigningKey.MASTER_KEY_ID));

    final PGPPublicKeyRingCollection keyRings = sut.getPublicKeyRings();
    assertTrue("Master key exists",
        keyRings.contains(RFC4880TestKeyringsDedicatedSigningKey.MASTER_KEY_ID));
    assertTrue("Encryption key exists",
        keyRings.contains(RFC4880TestKeyringsDedicatedSigningKey.ENCRYPTION_KEY));
    assertTrue("Active Signature Key key exists",
        keyRings.contains(RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_ACTIVE));
    assertTrue("Expired Signature key exists",
        keyRings.contains(RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_EXPIRED));
    assertTrue("Revokes Signature key exists",
        keyRings.contains(RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_REVOKED));
    assertTrue("Authentication key exists",
        keyRings.contains(RFC4880TestKeyringsDedicatedSigningKey.AUTHENTICATION_KEY));
  }


  @Test
  public void validate_privateKey_TestSetup() throws IOException, PGPException {
    final KeyringConfig sut = RFC4880TestKeyringsDedicatedSigningKey
        .publicAndPrivateKeyKeyringConfig();

    final PGPSecretKeyRingCollection keyRings = sut.getSecretKeyRings();

    assertTrue("Master key exists",
        keyRings.contains(RFC4880TestKeyringsDedicatedSigningKey.MASTER_KEY_ID));
    assertTrue("Encryption key exists",
        keyRings.contains(RFC4880TestKeyringsDedicatedSigningKey.ENCRYPTION_KEY));
    assertTrue("Active Signature Key key exists",
        keyRings.contains(RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_ACTIVE));
    assertTrue("Expired Signature key exists",
        keyRings.contains(RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_EXPIRED));
    assertTrue("Revokes Signature key exists",
        keyRings.contains(RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_REVOKED));
    assertTrue("Authentication key exists",
        keyRings.contains(RFC4880TestKeyringsDedicatedSigningKey.AUTHENTICATION_KEY));
  }


  @Test
  public void validate_expiredKey_isExpired() throws IOException, PGPException {
    final KeyringConfig sut = RFC4880TestKeyringsDedicatedSigningKey.publicKeyOnlyKeyringConfig();

    final PGPPublicKeyRingCollection keyRings = sut.getPublicKeyRings();
    final PGPPublicKey publicKey = keyRings
        .getPublicKey(RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_EXPIRED);

    assertNotNull("Expired Signature key exists", publicKey);

    assertEquals("Expired key has correct creation date set", EXPIRED_KEY_CREATION_TIME,
        publicKey.getCreationTime().toInstant());
    assertEquals("Expired key has correct expiry time set", 86450, publicKey.getValidSeconds());
  }


  @Test
  public void validate_revokedKey_isRevoked() throws IOException, PGPException {
    final KeyringConfig sut = RFC4880TestKeyringsDedicatedSigningKey.publicKeyOnlyKeyringConfig();

    final PGPPublicKeyRingCollection keyRings = sut.getPublicKeyRings();
    final PGPPublicKey publicKey = keyRings
        .getPublicKey(RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_REVOKED);

    assertNotNull("Revoked Signature key exists", publicKey);

    assertEquals("Revoked does not expire", 0, publicKey.getValidSeconds());
    assertTrue("Revoked key is revoked", publicKey.hasRevocation());
  }


  @Test
  public void validate_goodSignatureKey_isSignatureKey() throws IOException, PGPException {
    final KeyringConfig sut = RFC4880TestKeyringsDedicatedSigningKey
        .publicAndPrivateKeyKeyringConfig();

    final PGPPublicKeyRingCollection keyRings = sut.getPublicKeyRings();
    final PGPPublicKey publicKey = keyRings
        .getPublicKey(RFC4880TestKeyringsDedicatedSigningKey.SIGNATURE_KEY_ACTIVE);

    assertNotNull("Active Signature key exists", publicKey);

    assertEquals("Active Signature key does not expire", 0, publicKey.getValidSeconds());
    assertFalse("Active Signature key not revoked", publicKey.hasRevocation());
  }


}