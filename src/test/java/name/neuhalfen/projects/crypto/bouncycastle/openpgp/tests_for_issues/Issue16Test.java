package name.neuhalfen.projects.crypto.bouncycastle.openpgp.tests_for_issues;


import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.time.Instant;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.RFC4880TestKeyrings;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;
import org.junit.Before;
import org.junit.Test;

public class Issue16Test {


  @Before
  public void installBCProvider() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  public void issue16_encryotToStdout()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    final byte[] expectedPlaintext = ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes("US-ASCII");

    byte[] bytes;
    try (
        final ByteArrayInputStream is = new ByteArrayInputStream(expectedPlaintext);
        final ByteArrayOutputStream byteOutput = new ByteArrayOutputStream();

        final OutputStream outputStream = BouncyGPG
            .encryptToStream()
            .withConfig(RFC4880TestKeyrings.publicAndPrivateKeyKeyringConfig())
            .setReferenceDateForKeyValidityTo(
                RFC4880TestKeyrings.SIGNATURE_KEY_GUARANTEED_EXPIRED_AT)
            .withStrongAlgorithms()
            .toRecipient("rfc4880@example.org")
            .andSignWith("rfc4880@example.org")
            .armorAsciiOutput()
            .andWriteTo(byteOutput)
    ) {
      Streams.pipeAll(is, outputStream);

      outputStream.close();
      bytes = byteOutput.toByteArray();
    }

    final String ciphertext = new String(bytes, "US-ASCII");
    System.out.println(
        "This should be to 'rfc4880@example.org' and also signed by 'rfc4880@example.org'\n\n\necho '"
            + ciphertext + "'| gpg -v -d");
  }


  @Test
  public void issue16_validateCorrectSigningKey_skipExpired()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    signAtDateAndValidateExpectedKey(RFC4880TestKeyrings.SIGNATURE_KEY_GUARANTEED_EXPIRED_AT,
        RFC4880TestKeyrings.SIGNATURE_KEY_ACTIVE);
  }

  @Test
  public void issue16_validateCorrectSigningKey_useLastValidKey()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    signAtDateAndValidateExpectedKey(RFC4880TestKeyrings.SIGNATURE_KEY_GUARANTEED_VALID_AT,
        RFC4880TestKeyrings.SIGNATURE_KEY_EXPIRED);
  }


  private void signAtDateAndValidateExpectedKey(Instant dateOfTimestampVerification,
      long expectedSignatureKey)
      throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {
    final byte[] expectedPlaintext = ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes("US-ASCII");

    byte[] bytes;
    try (
        final ByteArrayInputStream is = new ByteArrayInputStream(expectedPlaintext);
        final ByteArrayOutputStream byteOutput = new ByteArrayOutputStream();

        final OutputStream outputStream = BouncyGPG
            .encryptToStream()
            .withConfig(RFC4880TestKeyrings.publicAndPrivateKeyKeyringConfig())
            .setReferenceDateForKeyValidityTo(dateOfTimestampVerification)
            .withStrongAlgorithms()
            .toRecipient("rfc4880@example.org")
            .andSignWith("rfc4880@example.org")
            .armorAsciiOutput()
            .andWriteTo(byteOutput)
    ) {
      Streams.pipeAll(is, outputStream);

      outputStream.close();
      bytes = byteOutput.toByteArray();
    }

    ByteArrayOutputStream fileOutput = new ByteArrayOutputStream();

    try (
        final ByteArrayInputStream cipherTextStream = new ByteArrayInputStream(bytes);

        final BufferedOutputStream bufferedOut = new BufferedOutputStream(fileOutput);

        // test that the active key is used
        final InputStream plaintextStream = BouncyGPG
            .decryptAndVerifyStream()
            .withConfig(RFC4880TestKeyrings.publicAndPrivateKeyKeyringConfig())
            .setReferenceDateForKeyValidityTo(dateOfTimestampVerification)
            .andRequireSignatureFromAllKeys(expectedSignatureKey)
            .fromEncryptedInputStream(cipherTextStream)

    ) {
      Streams.pipeAll(plaintextStream, bufferedOut);
    }
  }


}
