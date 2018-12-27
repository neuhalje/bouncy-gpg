package name.neuhalfen.projects.crypto.bouncycastle.openpgp.integration;

import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Collection;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.KeyFlag;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.KeySpec;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.ECDHKeyType;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.RSAKeyType;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.curve.EllipticCurve;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.type.length.RsaLength;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.Commands;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.EncryptCommand.EncryptCommandResult;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.GPGExec;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.ImportCommand;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.Result;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.util.io.Streams;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameter;

/**
 * Test that gpg can encrypt to BouncyGPG generated keys.
 */
@RunWith(Parameterized.class)
public class GPGCanEncryptToBouncyGPGKeys {


  private final static String UID_JULIET = "Juliet Capulet <juliet@example.com>";
  private final static String EMAIL_JULIET = "juliet@example.com";

  private final static String PLAINTEXT = "See how she leans her cheek upon her hand.\n"
      + "O, that I were a glove upon that hand\n"
      + "That I might touch that cheek! (Romeo)";

  @Before
  public void setup() {
    BouncyGPG.registerProvider();
  }

  @FunctionalInterface
  private interface KeyRingGenerator {

    KeyringConfig generateKeyringWithBouncyGPG()
        throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException;
  }

  @Parameterized.Parameters
  public static Collection<KeyRingGenerator[]> keyRingGenerators() {
    return Arrays.asList(new KeyRingGenerator[][]{
            {GPGCanEncryptToBouncyGPGKeys::generateSimpleRSAKeyring},
            {GPGCanEncryptToBouncyGPGKeys::generateSimpleECCKeyring},
            {GPGCanEncryptToBouncyGPGKeys::generateComplexKeyring}
        }
    );
  }

  @Parameter
  public KeyRingGenerator keyRingGenerator;

  @Test
  public void gpgCanEncryptToGeneratedKeyPair()
      throws IOException, InterruptedException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

    // we generate a keyring for Juliet with BouncyGPG,
    // copy the public key to GPG,
    // encrypt a message in GPG,
    // and finally decrypt the message in BouncyGPG
    final KeyringConfig keyring = keyRingGenerator.generateKeyringWithBouncyGPG();

    final GPGExec gpg = new GPGExec();

    importPublicKeyInGPG(gpg, keyring.getPublicKeyRings());

    byte[] chiphertext = encryptMessageInGPG(gpg, PLAINTEXT, EMAIL_JULIET);

    String decryptedPlaintext = decrpytMessageInBouncyGPG(keyring, chiphertext);

    assertThat(decryptedPlaintext, equalTo(PLAINTEXT));
  }

  private String decrpytMessageInBouncyGPG(final KeyringConfig keyring, final byte[] chiphertext)
      throws IOException {

    final ByteArrayOutputStream output = new ByteArrayOutputStream();
    try (
        final InputStream cipherTextStream = new ByteArrayInputStream(chiphertext);

        final BufferedOutputStream bufferedOut = new BufferedOutputStream(output);

        final InputStream plaintextStream = BouncyGPG
            .decryptAndVerifyStream()
            .withConfig(keyring)
            .andIgnoreSignatures()
            .fromEncryptedInputStream(cipherTextStream);

    ) {
      Streams.pipeAll(plaintextStream, bufferedOut);
    } catch (NoSuchProviderException | IOException e) {
      fail(e.getMessage());
    }
    output.close();
    final String decrypted_message = new String(output.toByteArray());
    return decrypted_message;
  }

  private byte[] encryptMessageInGPG(final GPGExec gpg, final String plaintext,
      final String recipient) throws IOException, InterruptedException {

    final EncryptCommandResult encryptCommandResult = gpg
        .runCommand(Commands.encrypt(plaintext.getBytes(), recipient));
    assertEquals(0, encryptCommandResult.exitCode());

    return encryptCommandResult.getCiphertext();
  }

  private void importPublicKeyInGPG(final GPGExec gpg,
      final PGPPublicKeyRingCollection publicKeyRings) throws IOException, InterruptedException {
    final byte[] encoded = publicKeyRings.getEncoded();

    final Result<ImportCommand> importCommandResult = gpg.runCommand(Commands.importKey(encoded));

    assertEquals(0, importCommandResult.exitCode());
  }

  static KeyringConfig generateSimpleRSAKeyring()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    return BouncyGPG.createSimpleKeyring().simpleRsaKeyRing(UID_JULIET, RsaLength.RSA_3072_BIT);
  }

  static KeyringConfig generateSimpleECCKeyring()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
    return BouncyGPG.createSimpleKeyring().simpleEccKeyRing(UID_JULIET);
  }

  static KeyringConfig generateComplexKeyring()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {

    final KeyringConfig keyringConfig = BouncyGPG.createKeyring().withSubKey(
        KeySpec.getBuilder(ECDHKeyType.fromCurve(EllipticCurve.CURVE_NIST_P521))
            .withKeyFlags(KeyFlag.ENCRYPT_STORAGE, KeyFlag.ENCRYPT_COMMS)
            .withDefaultAlgorithms())
        .withMasterKey(
            KeySpec.getBuilder(RSAKeyType.withLength(RsaLength.RSA_2048_BIT))
                .withKeyFlags(KeyFlag.AUTHENTICATION, KeyFlag.CERTIFY_OTHER, KeyFlag.SIGN_DATA)
                .withDefaultAlgorithms())
        .withPrimaryUserId(UID_JULIET)
        .withoutPassphrase()
        .build();
    return keyringConfig;
  }
}
