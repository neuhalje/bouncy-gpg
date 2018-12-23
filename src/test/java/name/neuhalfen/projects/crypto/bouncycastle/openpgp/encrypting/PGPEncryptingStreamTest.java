package name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.DefaultPGPAlgorithmSuites;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPAlgorithmSuite;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.ExampleMessages;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;
import org.junit.Before;
import org.junit.Test;
import org.junit.runners.Parameterized;

public class PGPEncryptingStreamTest {

  @SuppressWarnings("WeakerAccess")
  @Parameterized.Parameter
  public /* NOT private */ PGPAlgorithmSuite algorithmSuite;

  /*
   * make sure that the tests work independently of the way the config has been created
   */
  @Parameterized.Parameters
  public static Object[] data() {
    return new Object[]{DefaultPGPAlgorithmSuites.strongSuite()};
  }

  @Before
  public void installBCProvider() {
    BouncyGPG.registerProvider();
  }

  @Test
  public void closing_is_idempotent()
      throws IOException, PGPException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
    final byte[] expectedPlaintext = ExampleMessages.IMPORTANT_QUOTE_TEXT.getBytes(
        "US-ASCII");

    try (
        final ByteArrayInputStream is = new ByteArrayInputStream(expectedPlaintext);
        final ByteArrayOutputStream byteOutput = new ByteArrayOutputStream()
    ) {
      // Use public API contract instead of local methods
      final OutputStream outputStream = BouncyGPG
          .encryptToStream()
          .withConfig(Configs.keyringConfigFromFilesForSender())
          .withStrongAlgorithms()
          .toRecipient("recipient@example.com")
          .andSignWith("sender@example.com")
          .binaryOutput()
          .andWriteTo(byteOutput);

      Streams.pipeAll(is, outputStream);

      outputStream.close();

      // Expect that this will not raise an exception
      outputStream.close();
    }
  }


}