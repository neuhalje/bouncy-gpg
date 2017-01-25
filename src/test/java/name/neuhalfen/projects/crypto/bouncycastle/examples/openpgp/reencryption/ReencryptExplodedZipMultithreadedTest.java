package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.DecryptWithOpenPGPInputStreamFactory;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.DecryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.EncryptWithOpenPGP;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.EncryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.testtooling.CatchCloseStream;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.testtooling.Configs;
import org.junit.Test;

import java.io.InputStream;

import static org.junit.Assume.assumeNotNull;
import static org.mockito.Mockito.mock;

public class ReencryptExplodedZipMultithreadedTest {
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(ReencryptExplodedZipMultithreadedTest.class);

    private ZipEntityStrategy dummyStrategy = mock(ZipEntityStrategy.class);

    private ReencryptExplodedZipMultithreaded sut() {
        return new ReencryptExplodedZipMultithreaded();
    }

    @Test
    public void reencrypting_smallZip_doesNotCrash_integrationTest() throws Exception {

        try (
                final InputStream exampleEncryptedZip = CatchCloseStream.wrap("encrypted", getClass().getClassLoader().getResourceAsStream("testdata/zip_encrypted_binary_signed.zip.gpg"))
        ) {
            assumeNotNull(exampleEncryptedZip);

            final EncryptionConfig encryptionConfig = Configs.buildConfigForEncryptionFromResources();
            final DecryptionConfig decryptionConfig = Configs.buildConfigForDecryptionFromResources();

            assumeNotNull(encryptionConfig);
            assumeNotNull(decryptionConfig);

            EncryptWithOpenPGP encryptWithOpenPGP = new EncryptWithOpenPGP(encryptionConfig);

            DecryptWithOpenPGPInputStreamFactory decription = new DecryptWithOpenPGPInputStreamFactory(decryptionConfig);

            try (
                    final InputStream plainTextStream = CatchCloseStream.wrap("plain", decription.wrapWithDecryptAndVerify(exampleEncryptedZip))
            ) {

                sut().explodeAndReencrypt(plainTextStream, this.dummyStrategy, encryptWithOpenPGP);
            }
        }
    }

}
