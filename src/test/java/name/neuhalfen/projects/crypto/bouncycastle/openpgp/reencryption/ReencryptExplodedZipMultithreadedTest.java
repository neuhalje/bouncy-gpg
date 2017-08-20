package name.neuhalfen.projects.crypto.bouncycastle.openpgp.reencryption;

import static org.junit.Assume.assumeNotNull;
import static org.mockito.Mockito.mock;

import java.io.InputStream;
import java.security.Security;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BouncyGPG;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BuildDecryptionInputStreamAPI;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BuildEncryptionOutputStreamAPI;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.CatchCloseStream;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

public class ReencryptExplodedZipMultithreadedTest {

  private final ZipEntityStrategy dummyStrategy = mock(ZipEntityStrategy.class);

  @Before
  public void installBCProvider() {
    if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
      Security.addProvider(new BouncyCastleProvider());
    }
  }

  @Test
  public void reencrypting_smallZip_doesNotCrash_integrationTest() throws Exception {

    try (
        final InputStream exampleEncryptedZip = CatchCloseStream.wrap("encrypted",
            getClass().getClassLoader()
                .getResourceAsStream("testdata/zip_encrypted_binary_signed.zip.gpg"))
    ) {
      assumeNotNull(exampleEncryptedZip);

      final KeyringConfig keyringConfig = Configs.keyringConfigFromResourceForRecipient();

      assumeNotNull(keyringConfig);

      final ReencryptExplodedZipMultithreaded reencryptExplodedZip = new ReencryptExplodedZipMultithreaded();

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
        reencryptExplodedZip
            .explodeAndReencrypt(decryptedSourceZIP, this.dummyStrategy, encryptionFactory);
      }
    }
  }

}
