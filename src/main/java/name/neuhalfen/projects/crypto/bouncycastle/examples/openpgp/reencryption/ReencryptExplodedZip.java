package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.StreamDecryption;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.EncryptWithOpenPGP;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.StreamEncryption;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

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
public class ReencryptExplodedZip {

    /**
     * The Constant LOGGER.
     */
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(ReencryptExplodedZip.class);

    public void explodeAndReencrypt(InputStream is, StreamDecryption source, StreamEncryption target, File destRootDir) throws Exception {


        final PipedOutputStream pos = new PipedOutputStream();

        final PipedInputStream pis = new PipedInputStream(pos);

        final ExplodeAndReencrypt reencrypt = new ExplodeAndReencrypt(pis, target, destRootDir);
        final Thread encryptionThread = new Thread(reencrypt, "Encryption Thread");

        encryptionThread.start();

        source.decryptAndVerify(is, pos);
        pos.flush();
        pos.close();
        is.close();

        encryptionThread.wait();

        if (reencrypt.e != null) {
            LOGGER.info("Error in re-encryption", reencrypt.e);

            throw reencrypt.e;
        }

        LOGGER.info("Done");
    }


    private static class ExplodeAndReencrypt implements Runnable {
        private final InputStream is;
        private final StreamEncryption target;
        private final File destRootDir;

        public Exception e;

        private ExplodeAndReencrypt(InputStream is, StreamEncryption target, File destRootDir) {
            this.is = is;
            this.target = target;
            this.destRootDir = destRootDir;
        }

        @Override
        public void run() {
            try {
                LOGGER.info("Unziping thread started");
                explodeAndReencrypt();
                this.e = null;
                LOGGER.info("Unziping thread stopped");
            } catch (Exception e) {
                this.e = e;
                LOGGER.warn("Unziping thread stopped with error",e);
            }

        }

        private void explodeAndReencrypt() throws IOException, SignatureException, NoSuchAlgorithmException {
            ZipInputStream zis = new ZipInputStream(is);
            ZipEntry entry;
            while ((entry = zis.getNextEntry()) != null) {

                if (entry.isDirectory()) {
                    final String dirName = entry.getName();
                    LOGGER.info("found directory '{}'", dirName);
                    File destPath = new File(destRootDir, dirName);
                    boolean success = destPath.mkdir();
                    if (!success) throw new IOException("Failed to create '" + destPath + "'");
                } else {
                    String fileName = entry.getName() + ".gpg";
                    LOGGER.info("found file '{}'", fileName);
                    File destPath = new File(destRootDir, fileName);
                    FileOutputStream fos = new
                            FileOutputStream(destPath);
                    target.encryptAndSign(zis, fos);
                    fos.close();
                }
            }

            zis.close();
            is.close();
            LOGGER.debug("ZIP input stream closed");
        }

    }
}

