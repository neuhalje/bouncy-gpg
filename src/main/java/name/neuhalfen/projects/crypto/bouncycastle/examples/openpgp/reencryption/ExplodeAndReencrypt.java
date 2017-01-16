package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.StreamEncryption;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;


class ExplodeAndReencrypt implements Runnable {

    private final ZipEntityStrategy entityHandlingStrategy;

    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(ExplodeAndReencrypt.class);

    private final InputStream is;
    private final StreamEncryption streamEncryption;

    public Exception e;

    ExplodeAndReencrypt(InputStream is, ZipEntityStrategy entityHandlingStrategy, StreamEncryption streamEncryption) {
        this.is = is;
        this.entityHandlingStrategy = entityHandlingStrategy;
        this.streamEncryption = streamEncryption;
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

    private final Pattern REMOVE_LEADING_RELATIVE_PATH = Pattern.compile("^(([.]{2,})|/|\\\\)*", Pattern.COMMENTS);

    private final Pattern REMOVE_DOT_DOT_REGEXP = Pattern.compile("[.]{2,}", Pattern.COMMENTS);
    private final Pattern REMOVE_FOLLOWING_REGEXP = Pattern.compile("[^a-zA-Z0-9_, +-./\\\\]", Pattern.COMMENTS);

    String rewriteName(String nameFromZip) {
        final String withOutLeadingRelativePath = REMOVE_LEADING_RELATIVE_PATH.matcher(nameFromZip).replaceAll("");
        final String withoutDotDot = REMOVE_DOT_DOT_REGEXP.matcher(withOutLeadingRelativePath).replaceAll("");
        final String sanitizedMiddlePart = REMOVE_FOLLOWING_REGEXP.matcher(withoutDotDot).replaceAll("");
        return sanitizedMiddlePart;
    }

    void explodeAndReencrypt() throws IOException, SignatureException, NoSuchAlgorithmException {
        boolean zipDataFound = false;
        final ZipInputStream zis = new ZipInputStream(is);


        try {
            ZipEntry entry;

            int numDirs = 0;
            int numFiles = 0;
            while ((entry = zis.getNextEntry()) != null) {

                final String sanitizedFileName = rewriteName(entry.getName());

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