package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting.DecryptWithOpenPGP;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.EncryptWithOpenPGP;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.StreamEncryption;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.testtooling.Configs;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.testtooling.HashingInputStream;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.testtooling.HashingOutputStream;
import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.testtooling.RandomDataInputStream;
import org.junit.Test;

import java.io.*;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.util.concurrent.*;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;


/**
 * Encrypt something and then decrypt it.
 * <p>
 * These are more integration tests than unit tests.
 */
public class EncryptAndDecryptIntegrationTest {

    @Test
    public void encryptRandomData_andThenDecryptIt_gives_correctPlaintext() throws IOException, NoSuchAlgorithmException, SignatureException, ExecutionException, InterruptedException {
        final StreamEncryption sutEnc = new EncryptWithOpenPGP(Configs.buildConfigForEncryptionFromResources());

        final String decryptedHash;
        final String inputHash;

        // plumbing
        try (
                final InputStream randomSource = someKnownInputData();
                final HashingInputStream inputHashStream = HashingInputStream.sha256(randomSource);

                //
                final PipedOutputStream pop = new PipedOutputStream();
                final PipedInputStream pip = new PipedInputStream(pop)
        ) {
            // test


            final ExecutorService executor = Executors.newSingleThreadExecutor();

            final Callable<AsyncDecryptionResult> decryptionResultCallable = new AsyncDecryptionResultCallable(pip);

            final Future<AsyncDecryptionResult> decryptionResultFuture = executor.submit(decryptionResultCallable);

            sutEnc.encryptAndSign(inputHashStream, pop);

            // need to close input stream before reading hash
            inputHashStream.close();
            inputHash = inputHashStream.toString();

            decryptedHash = decryptionResultFuture.get().hash;
        }
        assertThat("The decrypted output must be equal to the input", decryptedHash, is(equalTo(inputHash)));
    }


    private InputStream someKnownInputData() {
        try {
            return new ByteArrayInputStream("Lorem ipsum".getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 should be supported", e);
        }
    }


    private InputStream someRandomInputData(int len) {
        return new RandomDataInputStream(len);
    }


    private final static class AsyncDecryptionResult {
        final String hash;

        private AsyncDecryptionResult(String hash) {
            this.hash = hash;
        }
    }

    private static class AsyncDecryptionResultCallable implements Callable<AsyncDecryptionResult> {

        private final InputStream in;

        AsyncDecryptionResultCallable(PipedInputStream pip) {
            this.in = pip;
        }

        @Override
        public AsyncDecryptionResult call() throws Exception {
            final DecryptWithOpenPGP sutDec = new DecryptWithOpenPGP(Configs.buildConfigForDecryptionFromResources());
            HashingOutputStream outputHash = HashingOutputStream.sha256();
            sutDec.decryptAndVerify(in, outputHash);
            outputHash.close();

            return new AsyncDecryptionResult(outputHash.toString());
        }
    }
}
