package name.neuhalfen.projects.crypto.bouncycastle.openpgp.reencryption;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting.EncryptWithOpenPGP;

import java.io.InputStream;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/**
 * Takes a ZIP file, unpacks it in memory (streaming), and writes the files encrypted.
 * .
 * E.g. with a file  /tmp/my_zip.zip  created this way:
 * .
 * # find .
 * README
 * dir_a/file1
 * dir_a/file2
 * dir_b/dir_b1/file3
 * .
 * zip -r /tmp/my_zip.zip .
 * .
 * The class will unpack, an re-encrypt the following directory structure
 * .
 * # find .
 * README.gpg
 * dir_a/file1.gpg
 * dir_a/file2.gpg
 * dir_b/dir_b1/file3.gpg
 */
public class ReencryptExplodedZipMultithreaded {

    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(ReencryptExplodedZipMultithreaded.class);

    public void explodeAndReencrypt(final InputStream plainTextStreamOfZip, final ZipEntityStrategy zipEntityStrategy, final EncryptWithOpenPGP streamEncryption) throws Exception {

        // decrpytionCommand  decrypts  encryptedLargeZip -> plainTextSink
        // plainTextSource converts  plainTextSink into an InputStream
        // reencrypt parses the zip & encrypts  plainTextSource -> target

        final Callable<Boolean> encryptionTask = new Callable<Boolean>() {
            @Override
            public Boolean call() throws Exception {

                try {
                    LOGGER.trace("Unziping started");
                    final ExplodeAndReencrypt reencrypt = new ExplodeAndReencrypt(plainTextStreamOfZip, zipEntityStrategy, streamEncryption);

                    reencrypt.explodeAndReencrypt();
                    LOGGER.debug("Unziping stopped");
                } catch (Exception e) {
                    LOGGER.warn("Unziping stopped with error", e);
                    throw e;
                }
                return true;
            }
        };

        final ExecutorService executor = Executors.newSingleThreadExecutor();

        final Future<Boolean> encryptionDoneFuture = executor.submit(encryptionTask);

        //   Streams.pipeAll(plainTextStreamOfZip, plainTextSink);
        LOGGER.debug("Decryption done");
        LOGGER.trace("Waiting for Encryption Thread");

        // no real return value. Just make sure we wait for the thread
        // errors are thrown as exception
        encryptionDoneFuture.get();

        LOGGER.info("Done");
        executor.shutdown();
    }


}

