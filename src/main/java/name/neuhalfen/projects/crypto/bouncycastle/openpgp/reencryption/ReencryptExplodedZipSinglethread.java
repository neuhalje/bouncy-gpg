package name.neuhalfen.projects.crypto.bouncycastle.openpgp.reencryption;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting.EncryptWithOpenPGP;

import java.io.InputStream;

/**
 * @see ReencryptExplodedZipSinglethread
 */
public class ReencryptExplodedZipSinglethread {

    /**
     * The Constant LOGGER.
     */
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(ReencryptExplodedZipSinglethread.class);


    public void explodeAndReencrypt(InputStream plainTextStream, ZipEntityStrategy zipEntityStrategy, EncryptWithOpenPGP streamEncryption) throws Exception {

        final ExplodeAndReencrypt explodeAndReencrypt = new ExplodeAndReencrypt(plainTextStream, zipEntityStrategy, streamEncryption);
        explodeAndReencrypt.explodeAndReencrypt();
    }
}

