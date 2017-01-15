package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.Configs;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.DecryptWithOpenPGPInputStreamFactory;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.DecryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.EncryptWithOpenPGP;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.EncryptionConfig;
import org.junit.Test;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import static org.junit.Assume.assumeNotNull;
import static org.mockito.Mockito.mock;

public class ReencryptExplodedZipSinglethreadTest {
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(ReencryptExplodedZipSinglethreadTest.class);

    private ZipEntityStrategy dummyStrategy = new ZipEntityStrategy() {

        @Override
        public void handleDirectory(String sanitizedDirectoryName) throws IOException {

        }

        @Override
        public OutputStream createOutputStream(String sanitizedFileName) throws IOException {
            return mock(OutputStream.class);
        }
    };

    private ReencryptExplodedZipSinglethread sut() {
        return new ReencryptExplodedZipSinglethread();
    }

    @Test
    public void reencrypting_smallZip_doesNotCrash_integrationTest() throws Exception {

        try (
                final InputStream exampleEncryptedZip = CloseStream.wrap("encrypted", getClass().getClassLoader().getResourceAsStream("testdata/zip_encrypted_binary_signed.zip.gpg"));
        ) {
            assumeNotNull(exampleEncryptedZip);

            final EncryptionConfig encryptionConfig = Configs.buildConfigForEncryptionFromResources();
            final DecryptionConfig decryptionConfig = Configs.buildConfigForDecryptionFromResources();

            assumeNotNull(encryptionConfig);
            assumeNotNull(decryptionConfig);

            EncryptWithOpenPGP encryptWithOpenPGP = new EncryptWithOpenPGP(encryptionConfig);

            DecryptWithOpenPGPInputStreamFactory decription = new DecryptWithOpenPGPInputStreamFactory(decryptionConfig);

            try (
                    final InputStream plainTextStream = CloseStream.wrap("plain", decription.wrapWithDecryptAndVerify(exampleEncryptedZip));
            ) {

                sut().explodeAndReencrypt(plainTextStream, this.dummyStrategy, encryptWithOpenPGP);
            }
        }
    }

    private final static class CloseStream extends FilterInputStream {
        public static InputStream wrap(String name, InputStream is) {
            return new CloseStream(name, is);
        }

        final String name;

        protected CloseStream(final String name, InputStream in) {
            super(in);
            this.name = name;
        }

        @Override
        public void close() throws IOException {
            LOGGER.debug("Closing " + name);
            super.close();
        }
    }
}
