package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation;

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

public class KeyRingBuilderImplTest {

  @Before
  public void installBCProvider() {
    BouncyGPG.registerProvider();
  }

  private final static String UID_JULIET = "Juliet Capulet <juliet@example.com>";
  private final static String EMAIL_JULIET = "<juliet@example.com>";

  @Test
  public void simpleEcKeyRing_createsGoodKeys()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

    // Verify that 'simpleEcKeyRing' creates good keys (correct uid, keytype, ..)

    SimpleKeyRingBuilder sut = new KeyRingBuilderImpl();

    final KeyringConfig keyRingConfig = sut.simpleEcKeyRing(UID_JULIET);

    validateSimpleKeyRing(keyRingConfig);

    final Iterable<PGPSecretKeyRing> secretKeyRings = keyRingConfig.getSecretKeyRings();
    secretKeyRings.forEach(keyRing ->
        assertThat("We want ECC keys",
            keyRing,
            everyItem(
                allOf(
                    keyAlgorithmAnyOf(
                        PublicKeyAlgorithm.ECDSA, //  ECDSA master key and
                        PublicKeyAlgorithm.ECDH  //   ECDH sub-key
                    ),
                    hasKeyLength(256)
                )
            )));
  }


  @Test
  public void simpleRsaKeyRing_createsGoodKeys()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

    // Verify that 'simpleEcKeyRing' creates good keys (correct uid, keytype, ..)

    SimpleKeyRingBuilder sut = new KeyRingBuilderImpl();

    // short keys for execution speed
    final KeyringConfig keyRingConfig = sut.simpleRsaKeyRing(UID_JULIET, RsaLength.RSA_1024_BIT);

    validateSimpleKeyRing(keyRingConfig);

    final Iterable<PGPSecretKeyRing> secretKeyRings = keyRingConfig.getSecretKeyRings();
    secretKeyRings.forEach(keyRing ->
        assertThat("We want RSA keys of correct length",
            keyRing,
            everyItem(
                allOf(
                    keyAlgorithmAnyOf(
                        PublicKeyAlgorithm.RSA_GENERAL // ... consists of a single RSA master key
                    ),
                    hasKeyLength(RsaLength.RSA_1024_BIT)
                )
            )));
  }

  /*
   * simpleRsaKeyRing/simpleEcKeyRing should create unprotected keyrings that
   * allow encryption, and signature.
   */
  private void validateSimpleKeyRing(final KeyringConfig keyRing) throws IOException, PGPException {
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
  }
}