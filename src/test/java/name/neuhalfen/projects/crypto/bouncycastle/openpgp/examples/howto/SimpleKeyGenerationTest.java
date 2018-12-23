package name.neuhalfen.projects.crypto.bouncycastle.openpgp.examples.howto;

import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.examples.howto.TestEnAndDecryptionUtil.assertEncryptSignDecryptVerifyOk;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.KeyMatcher.hasKeyLength;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.KeyMatcher.keyAlgorithmAnyOf;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.KeyMatcher.secretKeyIsEncrypted;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.KeyMatcher.secretKeyRingForUid;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.KeyMatcher.secretKeyRingHasRoles;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.KeyMatcher.secretKeyringHasCorrectSubkeyPackets;
import static org.hamcrest.Matchers.allOf;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.iterableWithSize;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PublicKeyAlgorithm;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.length.RsaLength;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.KeyMatcher;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.SecretKeyringKeyRoleMatcher.KeyRole;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.util.Iterable;
import org.junit.Before;
import org.junit.Test;

/**
 * These tests show how to create keys via the simplified API.
 */
public class SimpleKeyGenerationTest {

  @Before
  public void installBCProvider() {
    BouncyGPG.registerProvider();
  }

  private final static String UID_JULIET = "Juliet Capulet <juliet@example.com>";
  private final static String EMAIL_JULIET = "<juliet@example.com>";

  /**
   * Creates a simple ECC KeyPair with 256 bit ECC bit keys and with a user-id for Juliet Capulet.
   *
   * The key ring consists of an ECDSAKeyType master key and an ECDHKeyType sub-key.
   * The ECDSAKeyType master key is used for signing messages and certifying the sub key.
   * The ECDHKeyType sub-key is used for encryption of messages.
   **/
  @Test
  public void createSimple_ECC_Keyring()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException {

    final KeyringConfig eccKeyRing = BouncyGPG.createSimpleKeyring().simpleEccKeyRing(UID_JULIET);

    validateSimpleKeyRing(eccKeyRing);

    final Iterable<PGPSecretKeyRing> secretKeyRings = eccKeyRing.getSecretKeyRings();
    secretKeyRings.forEach(keyRing ->
        assertThat("We want ECC keys",
            keyRing,
            everyItem(
                allOf(
                    keyAlgorithmAnyOf(
                        PublicKeyAlgorithm.ECDSA, //  ECDSAKeyType master key and
                        PublicKeyAlgorithm.ECDH  //   ECDHKeyType sub-key
                    ),
                    hasKeyLength(256)
                )
            )));
  }


  /**
   * Creates a simple RSA KeyPair with 3072 bit keys and with a user-id for Juliet Capulet.
   *
   * The KeyPair consists of a single RSA master key which is used for signing, encryption and
   * certification.
   **/
  @Test
  public void createSimple_RSA_Keyring()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException {

    final KeyringConfig rsaKeyRing = BouncyGPG.createSimpleKeyring()
        .simpleRsaKeyRing(UID_JULIET, RsaLength.RSA_3072_BIT);

    validateSimpleKeyRing(rsaKeyRing);

    final Iterable<PGPSecretKeyRing> secretKeyRings = rsaKeyRing.getSecretKeyRings();
    secretKeyRings.forEach(keyRing ->
        assertThat("We want RSA keys of correct length",
            keyRing,
            everyItem(
                allOf(
                    keyAlgorithmAnyOf(
                        PublicKeyAlgorithm.RSA_GENERAL // ... consists of a single RSA master key
                    ),
                    hasKeyLength(RsaLength.RSA_3072_BIT)
                )
            )));
  }

  /*
   * simpleRsaKeyRing/simpleEccKeyRing should create unprotected keyrings that
   * allow encryption, and signature.
   */
  private void validateSimpleKeyRing(final KeyringConfig keyRing)
      throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
    assertNotNull("A keyring should be created", keyRing);

    final PGPPublicKeyRingCollection pubKeyRings = keyRing.getPublicKeyRings();
    assertThat("Juliet's public key should be created",
        pubKeyRings, contains(
            KeyMatcher.pubKeyRingForUid(EMAIL_JULIET)
        ));

    assertThat("Only one public key should be created",
        pubKeyRings, iterableWithSize(1)
    );

    final PGPSecretKeyRingCollection secretKeyRings = keyRing.getSecretKeyRings();
    assertThat("Juliet's secret key should be created",
        secretKeyRings,

        contains(
            secretKeyRingForUid(EMAIL_JULIET)
        ));

    assertThat("Juliet's secret key should have all roles",
        secretKeyRings,

        contains(
            secretKeyRingHasRoles(KeyRole.MASTER, KeyRole.ENCRYPTION, KeyRole.SIGNING)
        ));
    assertThat("Only one secret key should be created",
        secretKeyRings, iterableWithSize(1)
    );

    assertThat("No passphrase should be set",
        secretKeyRings, everyItem(not(secretKeyIsEncrypted())));

    // see https://github.com/bcgit/bc-java/issues/381
    assertThat("Keys should be exportable", secretKeyRings,
        everyItem(secretKeyringHasCorrectSubkeyPackets()));

    assertEncryptSignDecryptVerifyOk(keyRing, UID_JULIET);
  }
}