package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks;

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
public class RFC4880TestKeyringsMasterKeyAsSigningKeySanityTest {

  @Before
  public void before() {
    BouncyGPG.registerProvider();
  }

  @Test
  public void publicKeys_containsOnlyOneCollection() throws IOException, PGPException {
    final KeyringConfig sut = RFC4880TestKeyringsMasterKeyAsSigningKey.publicKeyOnlyKeyringConfig();
    assertEquals("Only one public keyring in the sut", 1, sut.getPublicKeyRings().size());
  }

  @Test
  public void privateKeys_containsOnlyOneCollection() throws IOException, PGPException {
    final KeyringConfig sut = RFC4880TestKeyringsMasterKeyAsSigningKey
        .publicAndPrivateKeyKeyringConfig();
    assertEquals("Only one private keyring in the sut", 1, sut.getSecretKeyRings().size());
  }

  @Test
  public void validate_pubKeyOnly_TestSetup() throws IOException, PGPException {
    final KeyringConfig sut = RFC4880TestKeyringsMasterKeyAsSigningKey.publicKeyOnlyKeyringConfig();

    assertFalse("Master private key does not exist",
        sut.getSecretKeyRings().contains(RFC4880TestKeyringsMasterKeyAsSigningKey.MASTER_KEY_ID));

    final PGPPublicKeyRingCollection keyRings = sut.getPublicKeyRings();
    assertTrue("Master key exists",
        keyRings.contains(RFC4880TestKeyringsMasterKeyAsSigningKey.MASTER_KEY_ID));
    assertTrue("Encryption key exists",
        keyRings.contains(RFC4880TestKeyringsMasterKeyAsSigningKey.ENCRYPTION_KEY));
  }


  @Test
  public void validate_privateKey_TestSetup() throws IOException, PGPException {
    final KeyringConfig sut = RFC4880TestKeyringsMasterKeyAsSigningKey
        .publicAndPrivateKeyKeyringConfig();

    final PGPSecretKeyRingCollection keyRings = sut.getSecretKeyRings();

    assertTrue("Master key exists",
        keyRings.contains(RFC4880TestKeyringsMasterKeyAsSigningKey.MASTER_KEY_ID));
    assertTrue("Encryption key exists",
        keyRings.contains(RFC4880TestKeyringsMasterKeyAsSigningKey.ENCRYPTION_KEY));
  }


  @Test
  public void validate_masterKey_isSignatureKey() throws IOException, PGPException {
    final KeyringConfig sut = RFC4880TestKeyringsMasterKeyAsSigningKey
        .publicAndPrivateKeyKeyringConfig();

    final PGPPublicKeyRingCollection keyRings = sut.getPublicKeyRings();
    final PGPPublicKey publicKey = keyRings
        .getPublicKey(RFC4880TestKeyringsMasterKeyAsSigningKey.MASTER_KEY_ID);

    assertNotNull("Active Signature key exists", publicKey);

    assertEquals("Active Signature key does not expire", 0, publicKey.getValidSeconds());
    assertFalse("Active Signature key not revoked", publicKey.hasRevocation());
  }


}