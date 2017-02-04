package name.neuhalfen.projects.crypto.bouncycastle.openpgp;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting.DecryptWithOpenPGPInputStreamFactory;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting.DecryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting.SignatureValidationStrategies;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting.SignatureValidationStrategy;
import org.bouncycastle.openpgp.PGPException;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.InputStream;

/**
 * This class implements the builder for decrypting Streams.
 */
public class BuildDecryptionInputStreamAPI {

    @Nonnull
    private DecryptionConfig decryptionConfig;

    @Nonnull
    private SignatureValidationStrategy signatureCheckingMode;


    /* hide */
    BuildDecryptionInputStreamAPI() {
    }

    /**
     * Start building by passing in the decryption config.
     *
     * @param decryptionConfig
     * @return
     */
    public Validation withConfig(DecryptionConfig decryptionConfig) {
        if (decryptionConfig == null) {
            throw new IllegalArgumentException("decryptionConfig must not be null");
        }

        BuildDecryptionInputStreamAPI.this.decryptionConfig = decryptionConfig;
        return new Validation();
    }

    public class Validation {

        /**
         * Decryption will enforce that the ciphertext has been signed by ALL of the
         * public key ids passed.
         * <p>
         * Key-ids are long values. For example with the following keyring
         * <p>
         * # gpg -k --keyid-format=0xlong
         * ...
         * pub   2048R/0x3DF16BD7C3F280F3 2015-09-27
         * uid                 [ultimate] Rezi Recipient (Pasword: recipient) <recipient@example.com>
         * sub   2048R/0x54A3DB374F787AB7 2015-09-27
         * ...
         * <p>
         * -->
         * <p>
         * andRequireSignatureFromAllKeys(0x54A3DB374F787AB7L)
         *
         * @param publicKeyIds a valid signature from all of the passed keys is required. The keys MUST exist in the public keyring.
         * @return the next build step
         */
        public Build andRequireSignatureFromAllKeys(Long... publicKeyIds) {
            if (publicKeyIds == null || publicKeyIds.length == 0) {
                throw new IllegalArgumentException("publicKeyIds must not be null or empty");
            }

            BuildDecryptionInputStreamAPI.this.signatureCheckingMode = SignatureValidationStrategies.requireSignatureFromAllKeys(publicKeyIds);
            return new Build();
        }


        /**
         * Decryption will enforce that the ciphertext has been signed by ALL of the
         * public key ids passed.
         *
         * Key-ids are long values. For example with the following keyring
         *
         * # gpg -k --keyid-format=0xlong
         *
         *  pub   2048R/0x3DF16BD7C3F280F3 2015-09-27
         *  uid                 [ultimate] Rezi Recipient (Pasword: recipient) <recipient@example.com>
         *  sub   2048R/0x54A3DB374F787AB7 2015-09-27
         *
         *
         * -->
         *
         *  andRequireSignatureFromAllKeys("recipient@example.com")
         *
         * @param userIds a valid signature from all of the passed keys is required. The keys MUST exist in the public keyring.
         * @return the next build step
         */
        public Build andRequireSignatureFromAllKeys(String... userIds) throws PGPException, IOException {

            if (userIds == null || userIds.length == 0) {
                throw new IllegalArgumentException("userIds must not be null or empty");
            }

            BuildDecryptionInputStreamAPI.this.signatureCheckingMode = SignatureValidationStrategies.requireSignatureFromAllKeys(decryptionConfig.getPublicKeyRings(), userIds);
            return new Build();
        }

        /**
         * Enforce a valid signature from *any* public key in the keyring.
         *
         * Signatures of keys NOT present in the ekyring are ignored.
         *
         * @return next build step
         */
        public Build andValidateSomeoneSigned() {
            BuildDecryptionInputStreamAPI.this.signatureCheckingMode = SignatureValidationStrategies.requireAnySignature();
            return new Build();
        }

        /**
         * Ignore all, even ínvalid(!) signatures.
         *
         * @return next build step
         */
        public Build andIgnoreSignatures() {
            BuildDecryptionInputStreamAPI.this.signatureCheckingMode = SignatureValidationStrategies.ignoreSignatures();
            return new Build();
        }
    }

    public class Build {

        /**
         * Build the final decrypted input stream.
         *
         * Signatures are verified AFTER decryption (reading the whole(!) plaintext stream).
         *
         * @param encryptedData  An encrypted input stream. Will not be closed.
         * @return Plaintext stream. Signatures are checked the moment EOF is reached.
         * @throws IOException IO is dangerous. Also wraps several GPG exceptions.
         */
        public InputStream fromEncryptedInputStream(InputStream encryptedData) throws IOException {
            if (encryptedData == null) {
                throw new IllegalArgumentException("encryptedData must not be null");
            }

            final DecryptWithOpenPGPInputStreamFactory pgpInputStreamFactory =
                    DecryptWithOpenPGPInputStreamFactory.create(BuildDecryptionInputStreamAPI.this.decryptionConfig,
                            BuildDecryptionInputStreamAPI.this.signatureCheckingMode);

            return pgpInputStreamFactory.wrapWithDecryptAndVerify(encryptedData);
        }
    }
}
