package name.neuhalfen.projects.crypto.bouncycastle.openpgp.integration;

import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.integration.BouncyGPGCanEncryptToGPG.TestFixture.testFixture;
import static org.junit.Assert.assertEquals;
import static org.junit.Assume.assumeTrue;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.Arrays;
import java.util.Collection;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.KeyFlag;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.KeySpec;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.ECDHKeyType;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.RSAKeyType;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.curve.EllipticCurve;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.length.RsaLength;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.Commands;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.DecryptCommand.DecryptCommandResult;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.GPGExec;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.VersionCommand.VersionCommandResult;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.hamcrest.Matchers;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;

/**
 * Test that BouncyGPG can encrypt a messages that GPG can decrypt.
 */
@RunWith(Parameterized.class)
public class BouncyGPGCanEncryptToGPG {


  private final static String UID_JULIET = "Juliet Capulet <juliet@example.com>";
  private final static String EMAIL_JULIET = "juliet@example.com";
  private final static String PASSPHRASE = null; // no passphrase

  private final static String PLAINTEXT = "See how she leans her cheek upon her hand.\n"
      + "O, that I were a glove upon that hand\n"
      + "That I might touch that cheek! (Romeo)";


  @Parameter(value = 0)
  public String testName;

  @Parameter(value = 1)
  public TestFixture fixtureStrategies;

  @Parameterized.Parameters(name = "{index}: {0}")
  public static Collection<Object[]> keyRingGenerators() {
    return Arrays.asList(new Object[][]{
            {
                "Simple RSA keyring",
                testFixture(BouncyGPGCanEncryptToGPG::generateSimpleRSAKeyring)},
            {
                "Simple ECC keyring",
                testFixture(BouncyGPGCanEncryptToGPG::generateSimpleECCKeyring)
            },
            {
                "Complex ECC keyring",
                testFixture(BouncyGPGCanEncryptToGPG::generateComplexKeyring)
            }
        }
    );
  }

  static KeyringConfig generateSimpleRSAKeyring(VersionCommandResult gpgVersion)
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    return BouncyGPG.createSimpleKeyring().simpleRsaKeyRing(UID_JULIET, RsaLength.RSA_3072_BIT);
  }

  static KeyringConfig generateSimpleECCKeyring(VersionCommandResult gpgVersion)
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    assumeTrue("Require at least GPG 2.1 for ECC", gpgVersion.isAtLeast(2, 1));

    return BouncyGPG.createSimpleKeyring().simpleEccKeyRing(UID_JULIET);
  }

  static KeyringConfig generateComplexKeyring(VersionCommandResult gpgVersion)
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    assumeTrue("Require at least GPG 2.1 for ECC", gpgVersion.isAtLeast(2, 1));

    final KeyringConfig keyringConfig = BouncyGPG.createKeyring().withSubKey(
        KeySpec.getBuilder(ECDHKeyType.fromCurve(EllipticCurve.CURVE_NIST_P521))
            .allowKeyToBeUsedTo(KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS)
            .withDefaultAlgorithms())
        .withMasterKey(
            KeySpec.getBuilder(RSAKeyType.withLength(RsaLength.RSA_2048_BIT))
                .allowKeyToBeUsedTo(KeyFlag.AUTHENTICATION, KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                .withDefaultAlgorithms())
        .withPrimaryUserId(UID_JULIET)
        .withoutPassphrase()
        .build();
    return keyringConfig;
  }

  @Before
  public void setup() {
    BouncyGPG.registerProvider();
  }

  @Test
  public void gpgCanEncryptToGeneratedKeyPair()
      throws IOException, InterruptedException, PGPException, NoSuchAlgorithmException,
      NoSuchProviderException, InvalidAlgorithmParameterException, SignatureException {

    // we generate a keyring for Juliet with BouncyGPG.
    // copy the private key to GPG,
    // encrypt a message in BouncyGPG,
    // and finally decrypt the message in gpg
    final GPGExec gpg = GPGExec.newInstance();

    final KeyringConfig keyring = fixtureStrategies.keyRingGenerator
        .generateKeyringWithBouncyGPG(gpg.version());

    exportPrivateKeyToGPG(gpg, keyring.getSecretKeyRings(), PASSPHRASE);

    byte[] chiphertext = encryptMessageInBouncyGPG(keyring, PLAINTEXT, EMAIL_JULIET, EMAIL_JULIET);

    String decryptedPlaintext = decrpytMessageInGPG(gpg, chiphertext, PASSPHRASE);

    Assert.assertThat(decryptedPlaintext, Matchers.equalTo(PLAINTEXT));
  }

  private String decrpytMessageInGPG(final GPGExec gpg,
      final byte[] chiphertext, final String passphrase)
      throws IOException, InterruptedException {

    final DecryptCommandResult result = gpg.runCommand(Commands.decrypt(chiphertext, passphrase));
    assertEquals(0, result.exitCode());
    return new String(result.getPlaintext());
  }

  private byte[] encryptMessageInBouncyGPG(final KeyringConfig keyringConfig,
      final String plaintext,
      final String recipient,
      final String sender)
      throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {

    ByteArrayOutputStream result = new ByteArrayOutputStream();

    try (
        BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(result, 16384 * 1024);

        final OutputStream outputStream = BouncyGPG
            .encryptToStream()
            .withConfig(keyringConfig)
            .withStrongAlgorithms()
            .toRecipients(recipient)
            .andSignWith(sender)
            .binaryOutput()
            .andWriteTo(bufferedOutputStream);
        // Maybe read a file or a webservice?
        final ByteArrayInputStream is = new ByteArrayInputStream(plaintext.getBytes())
    ) {
      Streams.pipeAll(is, outputStream);
      // It is very important that outputStream is closed before the result stream is read.
      // The reason is that GPG writes the signature at the end of the stream.
      // This is triggered by closing the stream.
      // In this example outputStream is closed via the try-with-resources mechanism of Java
    }

    result.close();
    return result.toByteArray();
  }

  private void exportPrivateKeyToGPG(final GPGExec gpg,
      final PGPSecretKeyRingCollection secretKeyRings,
      @Nullable final String passphrase)
      throws IOException, InterruptedException {

    final byte[] encoded = secretKeyRings.getEncoded();
    assertEquals(0, gpg
        .runCommand(
            Commands.importKey(encoded, passphrase)
        ).exitCode());
  }

  @FunctionalInterface
  private interface KeyRingGenerator {

    KeyringConfig generateKeyringWithBouncyGPG(VersionCommandResult gpgVersion)
        throws IOException, PGPException, NoSuchAlgorithmException,
        NoSuchProviderException, InvalidAlgorithmParameterException;
  }

  final static class TestFixture {

     final KeyRingGenerator keyRingGenerator;

    private TestFixture(
        final KeyRingGenerator keyRingGenerator) {
      this.keyRingGenerator = keyRingGenerator;
    }

     static TestFixture testFixture(KeyRingGenerator generator) {
      return new TestFixture(generator);
    }
  }
}
