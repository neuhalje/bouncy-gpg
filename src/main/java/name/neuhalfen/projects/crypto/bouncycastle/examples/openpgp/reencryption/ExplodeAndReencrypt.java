package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.StreamEncryption;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;


class ExplodeAndReencrypt {

    private final ZipEntityStrategy entityHandlingStrategy;

    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(ExplodeAndReencrypt.class);

    private final InputStream is;
    private final StreamEncryption streamEncryption;


    public ExplodeAndReencrypt(InputStream is, ZipEntityStrategy entityHandlingStrategy, StreamEncryption streamEncryption) {
        this.is = is;
        this.entityHandlingStrategy = entityHandlingStrategy;
        this.streamEncryption = streamEncryption;
    }


    public void explodeAndReencrypt() throws IOException, SignatureException, NoSuchAlgorithmException {
        boolean zipDataFound = false;
        final ZipInputStream zis = new ZipInputStream(is);


        try {
            ZipEntry entry;

            int numDirs = 0;
            int numFiles = 0;
            while ((entry = zis.getNextEntry()) != null) {

                final String sanitizedFileName = entityHandlingStrategy.rewriteName(entry.getName());

                if (!entry.getName().equals(sanitizedFileName)) {
                    LOGGER.trace("Rewriting '{}' to '{}'", entry.getName(), sanitizedFileName);
                }

                if (!zipDataFound) {
                    // Inform the logger that this is indeed a ZIP file
                    zipDataFound = true;
                    LOGGER.trace("Found ZIP Data");
                }

                if (entry.isDirectory()) {
                    numDirs++;
                    LOGGER.debug("found directory '{}'", entry.getName());

                    entityHandlingStrategy.handleDirectory(sanitizedFileName);
                } else {
                    numFiles++;

                    LOGGER.debug("found file '{}'", entry.getName());

                    try (
                            final OutputStream outputStream = entityHandlingStrategy.createOutputStream(sanitizedFileName)
                    ) {
                        if (outputStream != null) {
                            streamEncryption.encryptAndSign(zis, outputStream);
                        } else {
                            LOGGER.trace("Ignore {}", entry.getName());
                        }
                    }
                }
            }
            if (zipDataFound) {
                LOGGER.debug("ZIP input stream closed. Created {} directories, and {} files.", numDirs, numFiles);
            }else {
                LOGGER.info("ZIP input stream closed. No ZIP data found.");
            }
        } finally {
            // IGNORE
        }
    }
}