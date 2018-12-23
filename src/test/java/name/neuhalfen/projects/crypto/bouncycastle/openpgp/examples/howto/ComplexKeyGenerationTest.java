package name.neuhalfen.projects.crypto.bouncycastle.openpgp.examples.howto;

import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.examples.howto.TestEnAndDecryptionUtil.assertEncryptSignDecryptVerifyOk;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.KeyMatcher.secretKeyIsEncrypted;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.KeyMatcher.secretKeyRingForUid;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.KeyMatcher.secretKeyRingHasRoles;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.KeyMatcher.secretKeyringHasCorrectSubkeyPackets;
import static org.hamcrest.Matchers.contains;
import static org.hamcrest.Matchers.everyItem;
import static org.hamcrest.Matchers.iterableWithSize;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.Feature;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPCompressionAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPHashAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPSymmetricEncryptionAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.KeyFlag;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.KeySpec;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.KeySpecBuilder;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.Passphrase;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.ECDSAKeyType;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.RSAForEncryptionKeyType;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.curve.EllipticCurve;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.length.RsaLength;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.KeyMatcher;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher.SecretKeyringKeyRoleMatcher.KeyRole;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.junit.Before;
import org.junit.Test;

/**
 * These tests show how to create keys via the fine grained API.
 */
public class ComplexKeyGenerationTest {

  private final static String UID_JULIET = "Juliet Capulet <juliet@example.com>";
  private final static String EMAIL_JULIET = "<juliet@example.com>";

  @Before
  public void installBCProvider() {
    BouncyGPG.registerProvider();
  }

  /**
   * Creates a simple RSA KeyPair with 256 bit ECC bit keys and with a user-id for Juliet Capulet.
   *
   * The key ring consists of an ECDSAKeyType master key and an ECDHKeyType sub-key.
   * The ECDSAKeyType master key is used for signing messages and certifying the sub key.
   * The ECDHKeyType sub-key is used for encryption of messages.
   **/
  @Test
  public void createComplexKeyRing()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException {

    final KeySpec signingSubey = KeySpecBuilder
        .newSpec(ECDSAKeyType.fromCurve(EllipticCurve.CURVE_P256))
        .withKeyFlags(KeyFlag.SIGN_DATA)
        .withDefaultAlgorithms();

    final KeySpec authenticationSubey = KeySpecBuilder
        .newSpec(RSAForEncryptionKeyType.withLength(RsaLength.RSA_3072_BIT))
        .withKeyFlags(KeyFlag.AUTHENTICATION)
        .withDefaultAlgorithms();

    final KeySpec encryptionSubey = KeySpecBuilder
        .newSpec(RSAForEncryptionKeyType.withLength(RsaLength.RSA_2048_BIT))
        .withKeyFlags(KeyFlag.ENCRYPT_COMMS, KeyFlag.ENCRYPT_STORAGE)
        .withDefaultAlgorithms();

    final KeySpec masterKey = KeySpecBuilder.newSpec(
        ECDSAKeyType.fromCurve(EllipticCurve.CURVE_P256)
    )
        .withKeyFlags(KeyFlag.CERTIFY_OTHER)
        .withDetailedConfiguration()
        .withPreferredSymmetricAlgorithms(
            PGPSymmetricEncryptionAlgorithms.recommendedAlgorithms()
        )
        .withPreferredHashAlgorithms(
            PGPHashAlgorithms.recommendedAlgorithms()
        )
        .withPreferredCompressionAlgorithms(
            PGPCompressionAlgorithms.recommendedAlgorithms()
        )
        .withFeature(Feature.MODIFICATION_DETECTION)
        .done();

    final KeyringConfig complexKeyRing = BouncyGPG
        .createKeyring()
        .withSubKey(signingSubey)
        .withSubKey(authenticationSubey)
        .withSubKey(encryptionSubey)
        .withMasterKey(masterKey)
        .withPrimaryUserId(UID_JULIET)
        .withPassphrase(Passphrase.fromString("s3cret"))
        .build();

    assertNotNull("A keyring should be created", complexKeyRing);

    final PGPPublicKeyRingCollection pubKeyRings = complexKeyRing.getPublicKeyRings();
    assertThat("Juliet's public key should be created",
        pubKeyRings, contains(
            KeyMatcher.pubKeyRingForUid(EMAIL_JULIET)
        ));

    assertThat("Only one public key should be created",
        pubKeyRings, iterableWithSize(1)
    );

    final PGPSecretKeyRingCollection secretKeyRings = complexKeyRing.getSecretKeyRings();
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

    assertThat("A passphrase should be set",
        secretKeyRings, everyItem(secretKeyIsEncrypted()));

    // see https://github.com/bcgit/bc-java/issues/381
    assertThat("Keys should be exportable", secretKeyRings,
        everyItem(secretKeyringHasCorrectSubkeyPackets()));


    assertEncryptSignDecryptVerifyOk(complexKeyRing, UID_JULIET);
  }


}