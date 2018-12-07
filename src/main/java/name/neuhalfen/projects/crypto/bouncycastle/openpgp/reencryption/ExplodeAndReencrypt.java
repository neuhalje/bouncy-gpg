package name.neuhalfen.projects.crypto.bouncycastle.openpgp.reencryption;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.BuildEncryptionOutputStreamAPI;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.internal.Preconditions;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.util.io.Streams;


final class ExplodeAndReencrypt {

  private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory
      .getLogger(ExplodeAndReencrypt.class);
  private final ZipEntityStrategy entityHandlingStrategy;
  private final BuildEncryptionOutputStreamAPI.Build encryptionFactory;


  @SuppressWarnings("PMD.DefaultPackage")
  ExplodeAndReencrypt( ZipEntityStrategy entityHandlingStrategy,
      BuildEncryptionOutputStreamAPI.Build encryptionFactory) {
    Preconditions.checkNotNull(entityHandlingStrategy, "entityHandlingStrategy must not be null");
    Preconditions.checkNotNull(encryptionFactory, "encryptionFactory must not be null");

    this.entityHandlingStrategy = entityHandlingStrategy;
    this.encryptionFactory = encryptionFactory;
  }


  @SuppressWarnings({"PMD.DefaultPackage","PMD.LawOfDemeter"})
  void explodeAndReencrypt(final InputStream inputStream)
      throws IOException, SignatureException, NoSuchAlgorithmException, PGPException, NoSuchProviderException {

    Preconditions.checkNotNull(inputStream, "inputStream must not be null");

    boolean zipDataFound = false;
    final ZipInputStream zis = new ZipInputStream(inputStream);

    ZipEntry entry;

    int numDirs = 0; // NOPMD: Need to initialize counter
    int numFiles = 0; // NOPMD: Need to initialize counter
    while ((entry = zis.getNextEntry()) != null) { // NOPMD

      final String sanitizedFileName = entityHandlingStrategy.rewriteName(entry.getName()); // NOPMD: False positive for 'UR'-anomaly

      if (!entry.getName().equals(sanitizedFileName)) { // NOPMD: Demeter
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
            final OutputStream outputStream = entityHandlingStrategy
                .createOutputStream(sanitizedFileName)
        ) {
          if (outputStream == null) {
            LOGGER.trace("Ignore {}", entry.getName());
          } else {
            final OutputStream encryptedSmallFromZIP = encryptionFactory.andWriteTo(outputStream);
            Streams.pipeAll(zis, encryptedSmallFromZIP);
            encryptedSmallFromZIP.flush();
            encryptedSmallFromZIP.close();
          }
        }
      }
    }
    if (zipDataFound) {
      LOGGER.debug("ZIP input stream closed. Created {} directories, and {} files.", numDirs,
          numFiles);
    } else {
      LOGGER.info("ZIP input stream closed. No ZIP data found.");
    }

  }
}