package name.neuhalfen.projects.crypto.bouncycastle.openpgp.integration;

import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.integration.BouncyGPGCanEncryptToGPG.TestFixture.testFixture;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.integration.KeyRingGenerators.EMAIL_JULIET;
import static name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.Commands.listPackets;
import static org.junit.Assert.assertEquals;

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
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.integration.KeyRingGenerators.KeyRingGenerator;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.Commands;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.DecryptCommand.DecryptCommandResult;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.GPGExec;
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


  private final static String NO_PASSPHRASE = null; // no passphrase
  private final static String WITH_PASSPHRASE = "This is secret";

  private final static String PLAINTEXT = "See how she leans her cheek upon her hand.\n"
      + "O, that I were a glove upon that hand\n"
      + "That I might touch that cheek! (Romeo)";


  @Parameter(value = 0)
  public String testName;

  @Parameter(value = 1)
  public TestFixture fixture;

  @Parameterized.Parameters(name = "{index}: {0}")
  public static Collection<Object[]> keyRingGenerators() {
    return Arrays.asList(new Object[][]{
            {
                "Simple RSA keyring without passphrase",
                testFixture(KeyRingGenerators::generateSimpleRSAKeyring,
                    NO_PASSPHRASE)

            },
            {
                "Complex RSA keyring with a passphrase",
                testFixture(KeyRingGenerators::generateComplexRSAKeyring,
                    WITH_PASSPHRASE)

            },
            {
                "Simple ECC keyring without passphrase",
                testFixture(KeyRingGenerators::generateSimpleECCKeyring,
                    NO_PASSPHRASE)
            },
            {
                "Complex ECC with RSA subkey keyring and passphrase",
                testFixture(KeyRingGenerators::generateComplexEccAndRSAKeyring,
                    WITH_PASSPHRASE)
            }
        }
    );
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

    final KeyringConfig keyring = fixture.keyRingGenerator
        .generateKeyringWithBouncyGPG(gpg.version(), fixture.passphrase);

    exportPrivateKeyToGPG(gpg, keyring.getSecretKeyRings(), NO_PASSPHRASE);
    gpg.runCommand(listPackets("Secret keyring", keyring.getSecretKeyRings().getEncoded()));

    byte[] chiphertext = encryptMessageInBouncyGPG(keyring, PLAINTEXT, EMAIL_JULIET, EMAIL_JULIET);
    gpg.runCommand(listPackets("Ciphertext", chiphertext));

    String decryptedPlaintext = decrpytMessageInGPG(gpg, chiphertext, fixture.passphrase);

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


  final static class TestFixture {

    final KeyRingGenerator keyRingGenerator;
    @Nullable
    final String passphrase;

    private TestFixture(
        final KeyRingGenerator keyRingGenerator, final String passphrase) {
      this.keyRingGenerator = keyRingGenerator;
      this.passphrase = passphrase;
    }

    public static TestFixture testFixture(KeyRingGenerator generator, @Nullable String passphrase) {
      return new TestFixture(generator, passphrase);
    }
  }

}
