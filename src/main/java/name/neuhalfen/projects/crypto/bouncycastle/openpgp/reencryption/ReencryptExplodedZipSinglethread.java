package name.neuhalfen.projects.crypto.bouncycastle.openpgp.reencryption;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BuildEncryptionOutputStreamAPI;

import java.io.InputStream;

/**
 * @see ReencryptExplodedZipSinglethread
 */
public class ReencryptExplodedZipSinglethread {

    /**
     * The Constant LOGGER.
     */
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(ReencryptExplodedZipSinglethread.class);


    public void explodeAndReencrypt(InputStream plainTextStream, ZipEntityStrategy zipEntityStrategy, BuildEncryptionOutputStreamAPI.Build encryptionFactory) throws Exception {

        final ExplodeAndReencrypt explodeAndReencrypt = new ExplodeAndReencrypt(plainTextStream, zipEntityStrategy, encryptionFactory);
        explodeAndReencrypt.explodeAndReencrypt();
    }
}

