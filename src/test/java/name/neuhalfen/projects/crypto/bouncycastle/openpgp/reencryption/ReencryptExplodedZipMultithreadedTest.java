package name.neuhalfen.projects.crypto.bouncycastle.openpgp.reencryption;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting.DecryptionStreamFactory;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting.EncryptWithOpenPGP;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting.EncryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.CatchCloseStream;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.Configs;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignatureValidationStrategies;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;

import java.io.InputStream;
import java.security.Security;

import static org.junit.Assume.assumeNotNull;
import static org.mockito.Mockito.mock;

public class ReencryptExplodedZipMultithreadedTest {
    @Before
    public void installBCProvider() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

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
            final KeyringConfig decryptionConfig = Configs.keyringConfigFromFilesForRecipient();

            assumeNotNull(encryptionConfig);
            assumeNotNull(decryptionConfig);

            EncryptWithOpenPGP encryptWithOpenPGP = new EncryptWithOpenPGP(encryptionConfig);

            DecryptionStreamFactory decription = new DecryptionStreamFactory(decryptionConfig, SignatureValidationStrategies.requireAnySignature());

            try (
                    final InputStream plainTextStream = CatchCloseStream.wrap("plain", decription.wrapWithDecryptAndVerify(exampleEncryptedZip))
            ) {

                sut().explodeAndReencrypt(plainTextStream, this.dummyStrategy, encryptWithOpenPGP);
            }
        }
    }

}
