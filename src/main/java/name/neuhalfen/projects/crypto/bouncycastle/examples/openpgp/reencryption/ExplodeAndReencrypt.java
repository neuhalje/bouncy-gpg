package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.StreamEncryption;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;


class ExplodeAndReencrypt implements Runnable {

    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(ReencryptExplodedZipMultithreaded.class);

    private final InputStream is;
    private final StreamEncryption target;
    private final File destRootDir;

    public Exception e;

    ExplodeAndReencrypt(InputStream is, StreamEncryption target, File destRootDir) {
        this.is = is;
        this.target = target;
        this.destRootDir = destRootDir;
    }

    @Override
    public void run() {
        try {
            LOGGER.trace("Unziping started");
            explodeAndReencrypt();
            this.e = null;
            LOGGER.debug("Unziping  stopped");
        } catch (Exception e) {
            this.e = e;
            LOGGER.warn("Unziping  stopped with error", e);
        }

    }

    private void explodeAndReencrypt() throws IOException, SignatureException, NoSuchAlgorithmException {
        ZipInputStream zis = new ZipInputStream(is);
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {

            if (entry.isDirectory()) {
                final String dirName = entry.getName();
                LOGGER.trace("found directory '{}'", dirName);
                File destPath = new File(destRootDir, dirName);
                boolean success = destPath.mkdir();
                if (!success) throw new IOException("Failed to create '" + destPath + "'");
            } else {
                String fileName = entry.getName() + ".gpg";
                LOGGER.trace("found file '{}'", fileName);
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
