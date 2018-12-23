package name.neuhalfen.projects.crypto.bouncycastle.openpgp.examples.howto;

import static org.junit.Assert.assertArrayEquals;

import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;

class TestEnAndDecryptionUtil {

  private TestEnAndDecryptionUtil() {/* util*/}

  public static void assertEncryptSignDecryptVerifyOk(KeyringConfig keyringConfigFrom, String uid)
      throws PGPException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
    assertEncryptSignDecryptVerifyOk(keyringConfigFrom, uid, uid, keyringConfigFrom);
  }

  public static void assertEncryptSignDecryptVerifyOk(KeyringConfig keyringConfigFrom, String encryptTo,
      String signWith, KeyringConfig keyringConfigTo)
      throws IOException, PGPException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException {

    final ByteArrayOutputStream result = new ByteArrayOutputStream();

    try (
        BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(result, 16384);
        final OutputStream outputStream = BouncyGPG
            .encryptToStream()
            .withConfig(keyringConfigFrom)
            .withStrongAlgorithms()
            .toRecipient(encryptTo)
            .andSignWith(signWith)
            .binaryOutput()
            .andWriteTo(bufferedOutputStream);

        final InputStream is = new ByteArrayInputStream(
            ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes())
    ) {
      Streams.pipeAll(is, outputStream);
    }

    final byte[] ciphertext = result.toByteArray();
    final ByteArrayOutputStream plainBA = new ByteArrayOutputStream();

    try (
        final InputStream plainIS = BouncyGPG.decryptAndVerifyStream()
            .withConfig(keyringConfigTo)
            .andRequireSignatureFromAllKeys(signWith)
            .fromEncryptedInputStream(new ByteArrayInputStream(ciphertext))

    ) {
      Streams.pipeAll(plainIS, plainBA);
    }

    assertArrayEquals(ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes(), plainBA.toByteArray());
  }
}
