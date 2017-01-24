package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.StreamDecryption;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.StreamEncryption;

import java.io.File;
import java.io.InputStream;
import java.io.PipedInputStream;
import java.io.PipedOutputStream;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

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

    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(ReencryptExplodedZipMultithreaded.class);

    public void explodeAndReencrypt(InputStream encryptedLargeZip, StreamDecryption decryptionCommand, final StreamEncryption target, final File destRootDir) throws Exception {

        // decrpytionCommand  decrypts  encryptedLargeZip -> plainTextSink
        // plainTextSource converts  plainTextSink into an InputStream
        // reencrypt parses the zip & encrypts  plainTextSource -> target

        final PipedOutputStream plainTextSink = new PipedOutputStream();
        final PipedInputStream plainTextSource = new PipedInputStream(plainTextSink);


        final Callable<Boolean> encryptionTask = new Callable<Boolean>() {
            @Override
            public Boolean call() throws Exception {

                try {
                    LOGGER.trace("Unziping started");
                    final ZipEntityStrategy zipEntityStrategy = new FSZipEntityStrategy(destRootDir);
                    final ExplodeAndReencrypt reencrypt = new ExplodeAndReencrypt(plainTextSource, zipEntityStrategy, target);

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
        decryptionCommand.decryptAndVerify(encryptedLargeZip, plainTextSink);

        LOGGER.debug("Decryption done");
        plainTextSink.flush();
        plainTextSink.close();
        plainTextSource.close();

        LOGGER.debug("Waiting for Encryption Thread");

        // no real return value. Just make sure we wait for the thread
        // errors are thrown as exception
        encryptionDoneFuture.get();

        LOGGER.info("Done");
        executor.shutdown();
    }


}

