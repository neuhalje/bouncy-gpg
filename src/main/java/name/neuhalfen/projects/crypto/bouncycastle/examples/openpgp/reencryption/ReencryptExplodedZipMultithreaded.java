package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.StreamDecryption;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.StreamEncryption;

import java.io.File;
import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;

/**
 * Takes a ZIP file, unpacks it in memory (streaming), and writes the files encrypted.
 * <p>
 * E.g. with a file  /tmp/my_zip.zip  created this way:
 * <p>
 * <verbatim>
 * # find .
 * README
 * dir_a/file1
 * dir_a/file2
 * dir_b/dir_b1/file3
 * <p>
 * zip -r /tmp/my_zip.zip .
 * <p>
 * </verbatim>
 * <p>
 * The class will unpack, an re-encrypt the following directory structure
 * <p>
 * <verbatim>
 * # find .
 * README.gpg
 * dir_a/file1.gpg
 * dir_a/file2.gpg
 * dir_b/dir_b1/file3.gpg
 * </verbatim>
 */
public class ReencryptExplodedZipMultithreaded {

    /**
     * The Constant LOGGER.
     */
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(ReencryptExplodedZipMultithreaded.class);

    public void explodeAndReencrypt(InputStream is, StreamDecryption source, StreamEncryption target, File destRootDir) throws Exception {


        final PipedOutputStream pos = new PipedOutputStream();

        final PipedInputStream pis = new PipedInputStream(pos);

        final ZipEntityStrategy zipEntityStrategy = new FSZipEntityStrategy(destRootDir);
        final ExplodeAndReencrypt reencrypt = new ExplodeAndReencrypt(pis, zipEntityStrategy, target);
        final Thread encryptionThread = new Thread(reencrypt, "Encryption Thread");

        encryptionThread.start();

        source.decryptAndVerify(is, pos);
        LOGGER.debug("Decryption done");
        pos.flush();
        LOGGER.debug("Close PipedOutputStream");

        pos.close();
        is.close();
        LOGGER.debug("Waiting for Encryption Thread");

        encryptionThread.wait();

        if (reencrypt.e != null) {
            LOGGER.info("Error in re-encryption", reencrypt.e);

            throw reencrypt.e;
        }

        LOGGER.info("Done");
    }


}

