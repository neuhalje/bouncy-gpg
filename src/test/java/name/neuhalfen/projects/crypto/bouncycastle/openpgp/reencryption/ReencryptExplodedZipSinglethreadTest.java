package name.neuhalfen.projects.crypto.bouncycastle.openpgp.reencryption;

import static org.junit.Assume.assumeNotNull;
import static org.mockito.Mockito.mock;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BuildDecryptionInputStreamAPI;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BuildEncryptionOutputStreamAPI;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.CatchCloseStream;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.DevNullOutputStream;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

public class ReencryptExplodedZipSinglethreadTest {

  private final ZipEntityStrategy dummyStrategy = mock(ZipEntityStrategy.class);

  @Before
  public void installBCProvider() {
    BouncyGPG.registerProvider();
  }

  @Test
  public void reencrypting_smallZip_mockStrategy_doesNotCrash_integrationTest() throws Exception {

    try (
        final InputStream exampleEncryptedZip = CatchCloseStream.wrap("encrypted",
            getClass().getClassLoader()
                .getResourceAsStream("testdata/zip_encrypted_binary_signed.zip.gpg"))
    ) {
      assumeNotNull(exampleEncryptedZip);

      final KeyringConfig keyringConfig = Configs.keyringConfigFromResourceForRecipient();

      assumeNotNull(keyringConfig);

      final ReencryptExplodedZipSinglethread reencryptExplodedZip = new ReencryptExplodedZipSinglethread();

      final BuildEncryptionOutputStreamAPI.Build encryptionFactory = BouncyGPG
          .encryptToStream()
          .withConfig(keyringConfig)
          .withStrongAlgorithms()
          .toRecipient("recipient@example.com")
          .andDoNotSign()
          .binaryOutput();

      final BuildDecryptionInputStreamAPI.Build decryptionFactory = BouncyGPG
          .decryptAndVerifyStream()
          .withConfig(keyringConfig)
          .andValidateSomeoneSigned();

      try (
          final InputStream decryptedSourceZIP = decryptionFactory
              .fromEncryptedInputStream(exampleEncryptedZip)
      ) {
        // The mock will return 'null' for each request
        reencryptExplodedZip
            .explodeAndReencrypt(decryptedSourceZIP, this.dummyStrategy, encryptionFactory);
      }
    }
  }

  @Test
  public void reencrypting_smallZip_doesNotCrashWhenEncryptingTheNestedFilesOfTheZip_integrationTest()
      throws Exception {

    try (
        final InputStream exampleEncryptedZip = CatchCloseStream.wrap("encrypted",
            getClass().getClassLoader()
                .getResourceAsStream("testdata/zip_encrypted_binary_signed.zip.gpg"))
    ) {
      assumeNotNull(exampleEncryptedZip);

      final KeyringConfig keyringConfig = Configs.keyringConfigFromResourceForRecipient();

      assumeNotNull(keyringConfig);

      final ReencryptExplodedZipSinglethread reencryptExplodedZip = new ReencryptExplodedZipSinglethread();

      final BuildEncryptionOutputStreamAPI.Build encryptionFactory = BouncyGPG
          .encryptToStream()
          .withConfig(keyringConfig)
          .withStrongAlgorithms()
          .toRecipient("recipient@example.com")
          .andDoNotSign()
          .binaryOutput();

      final BuildDecryptionInputStreamAPI.Build decryptionFactory = BouncyGPG
          .decryptAndVerifyStream()
          .withConfig(keyringConfig)
          .andValidateSomeoneSigned();

      ZipEntityStrategy writeToDevNullStrategy = new ZipEntityStrategy() {
        @Override
        public String rewriteName(String nameFromZip) {
          return nameFromZip;
        }

        @Override
        public void handleDirectory(String sanitizedDirectoryName) throws IOException {
          // ignore - nothing to do
        }

        @Nullable
        @Override
        public OutputStream createOutputStream(String sanitizedFileName) throws IOException {
          return new DevNullOutputStream();
        }
      };
      try (
          final InputStream decryptedSourceZIP = decryptionFactory
              .fromEncryptedInputStream(exampleEncryptedZip)
      ) {
        reencryptExplodedZip
            .explodeAndReencrypt(decryptedSourceZIP, writeToDevNullStrategy, encryptionFactory);
      }
    }
  }
}
