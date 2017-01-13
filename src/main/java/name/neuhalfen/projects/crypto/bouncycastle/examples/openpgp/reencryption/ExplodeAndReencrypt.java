package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.StreamEncryption;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.regex.Pattern;
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

    private final Pattern ILLEGAL_REGEXP = Pattern.compile("([.]{2,})|[^a-zA-Z0-9_, +-.]", Pattern.COMMENTS);

    protected String rewriteName(String nameFromZip) {
        return ILLEGAL_REGEXP.matcher(nameFromZip).replaceAll("");
    }

    public void explodeAndReencrypt() throws IOException, SignatureException, NoSuchAlgorithmException {
        boolean zipDataFound = false;

        ZipInputStream zis = new ZipInputStream(is);
        ZipEntry entry;

        int numDirs = 0;
        int numFiles = 0;

        try {
            while ((entry = zis.getNextEntry()) != null) {

                final String rewrittenEntryName = rewriteName(entry.getName());

                if (!zipDataFound) {
                    zipDataFound = true;
                    LOGGER.debug("Found ZIP Data");
                }

                if (entry.isDirectory()) {
                    numDirs++;
                    LOGGER.trace("found directory '{}'", entry.getName());

                    File destPath = new File(destRootDir, rewrittenEntryName);
                    boolean success = destPath.mkdir();
                    if (!success) throw new IOException("Failed to create '" + destPath + "'");
                } else {
                    numFiles++;

                    LOGGER.trace("found file '{}'", entry.getName());

                    final String fileName = rewrittenEntryName + ".gpg";

                    File destPath = new File(destRootDir, fileName);
                    FileOutputStream fos = new
                            FileOutputStream(destPath);
                    target.encryptAndSign(zis, fos);
                    fos.close();
                }
            }
        } finally {

            zis.close();
            is.close();
        }


        LOGGER.debug("ZIP input stream closed. Created {} directories, and {} files.", numDirs, numFiles);
    }

}
