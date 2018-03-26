package name.neuhalfen.projects.crypto.bouncycastle.openpgp;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.time.Instant;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting.DecryptionStreamFactory;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.Rfc4880KeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignatureValidationStrategies;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignatureValidationStrategy;
import org.bouncycastle.openpgp.PGPException;

/**
 * This class implements the builder for decrypting GPG-encrypted streams.
 */
@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.AccessorMethodGeneration", "PMD.LawOfDemeter"})
public final class BuildDecryptionInputStreamAPI {

  @Nonnull
  private KeyringConfig keyringConfig;
  @Nonnull
  private SignatureValidationStrategy signatureCheckingMode;

  private KeySelectionStrategy keySelectionStrategy = new Rfc4880KeySelectionStrategy(
      Instant.now());

  /**
   * Start building by passing in the keyring config.
   *
   * @param keyringConfig Keyring
   *
   * @return next build step
   */
  @Nonnull
  public ValidationWithKeySelectionStrategy withConfig(@Nullable KeyringConfig keyringConfig) {
    if (keyringConfig == null) {
      throw new IllegalArgumentException("keyringConfig must not be null");
    }

    BuildDecryptionInputStreamAPI.this.keyringConfig = keyringConfig;
    return new ValidationWithKeySelectionStrategy();
  }


  public final class ValidationWithKeySelectionStrategy extends ValidationImpl {

    private ValidationWithKeySelectionStrategy() {
      super();
      BuildDecryptionInputStreamAPI.this.keySelectionStrategy = new Rfc4880KeySelectionStrategy(
          Instant.now());
    }

    public Validation setReferenceDateForKeyValidityTo(
        Instant dateOfTimestampVerification) {
      if (dateOfTimestampVerification == null) {
        throw new IllegalArgumentException("dateOfTimestampVerification must not be null");
      }
      BuildDecryptionInputStreamAPI.this.keySelectionStrategy = new Rfc4880KeySelectionStrategy(
          dateOfTimestampVerification);
      return new ValidationImpl();
    }

    public Validation withKeySelectionStrategy(KeySelectionStrategy strategy) {
      if (strategy == null) {
        throw new IllegalArgumentException("strategy must not be null");
      }
      BuildDecryptionInputStreamAPI.this.keySelectionStrategy = strategy;
      return new ValidationImpl();
    }
  }


  public interface Build {

    /**
     * Build the final decrypted input stream.
     *
     * This method will start reading the cipherstream until it finds the encrypted plaintext.
     *
     * If the source data is NOT signed, but a signature is REQUIRED, then this function might
     * throw.
     *
     * Signatures are verified AFTER decryption (reading the whole(!) plaintext stream). In this
     * case the returned InputStream will validate the signatures.
     *
     * @param encryptedData An encrypted input stream. <b>Will not be closed</b>.
     *
     * @return Plaintext stream. Signatures are checked the moment EOF is reached.
     *
     * @throws IOException IO is dangerous. Also wraps several GPG exceptions.
     * @throws NoSuchProviderException BC provider is not registered
     */
    @Nonnull
    InputStream fromEncryptedInputStream(@Nullable InputStream encryptedData)
        throws IOException, NoSuchProviderException;
  }

  public interface Validation {

    /**
     * Decryption will enforce that the ciphertext has been signed by ALL of the public key ids
     * passed.
     *
     * Given  the following keyring:
     *
     * <pre>{@code markdown: text
     * $ gpg -k --keyid-format=0xlong
     *
     * ... pub 2048R/0x3DF16BD7C3F280F3 ... uid [ultimate] ...  <signer@example.com>
     * ... sub 2048R/0x54A3DB374F787AB7 ... [S] ... }</pre>
     *
     * To require a valid signature from {@code signer@example.com} with the following keyring, call
     *
     * {@code ...andRequireSignatureFromAllKeys(0x54A3DB374F787AB7L)}:
     *
     * @param publicKeyIds A valid signature from ALL of the passed keys is required. Each key MUST
     * exist in the public keyring.
     *
     * @return the next build step
     */
    @Nonnull
    Build andRequireSignatureFromAllKeys(@Nullable Long... publicKeyIds);

    /**
     * Decryption will enforce that the ciphertext has been signed by ALL of the public key ids
     * passed.
     *
     * Given  the following keyring:
     *
     * <pre>{@code markdown: text
     * $ gpg -k --keyid-format=0xlong
     *
     * ... pub 2048R/0x3DF16BD7C3F280F3 ... uid [ultimate] ...  <signer@example.com>
     * ... sub 2048R/0x54A3DB374F787AB7 ... [S] ... }</pre>
     *
     * To require a valid signature from {@code signer@example.com} with the following keyring, call
     *
     * {@code ...andRequireSignatureFromAllKeys("signer@example.com")}
     *
     * @param userIds a valid signature from all of the passed uids is required. The keys MUST exist
     * in the public keyring.
     *
     * @return the next build step
     *
     * @throws PGPException error extracting public keys from keyring
     * @throws IOException IO is dangerous. Accessing the keyring might touch the filesystem.
     */
    @Nonnull
    Build andRequireSignatureFromAllKeys(@Nullable String... userIds)
        throws PGPException, IOException;

    /**
     * Enforce a valid signature from *any* public key in the keyring. . Signatures of keys NOT
     * present in the keyring are IGNORED (treated as not existing).
     *
     * @return next build step
     */
    @Nonnull
    Build andValidateSomeoneSigned();

    /**
     * Ignore all, even invalid(!) signatures.
     *
     * @return next build step
     */
    @Nonnull
    Build andIgnoreSignatures();
  }

  private class ValidationImpl implements Validation {

    @Override
    @Nonnull
    public Build andRequireSignatureFromAllKeys(@Nullable Long... publicKeyIds) {
      if (publicKeyIds == null || publicKeyIds.length == 0) {
        throw new IllegalArgumentException("publicKeyIds must not be null or empty");
      }

      BuildDecryptionInputStreamAPI.this.signatureCheckingMode = SignatureValidationStrategies
          .requireSignatureFromAllKeys(publicKeyIds);
      return new Builder();
    }


    @Override
    @Nonnull
    public Build andRequireSignatureFromAllKeys(@Nullable String... userIds)
        throws PGPException, IOException {

      if (userIds == null || userIds.length == 0) {
        throw new IllegalArgumentException("userIds must not be null or empty");
      }
      BuildDecryptionInputStreamAPI.this.signatureCheckingMode = SignatureValidationStrategies
          .requireSignatureFromAllUids(keySelectionStrategy, keyringConfig, userIds);
      return new Builder();
    }

    @Override
    @Nonnull
    public Build andValidateSomeoneSigned() {
      BuildDecryptionInputStreamAPI.this.signatureCheckingMode = SignatureValidationStrategies
          .requireAnySignature();
      return new Builder();
    }

    @Override
    @Nonnull
    public Build andIgnoreSignatures() {
      BuildDecryptionInputStreamAPI.this.signatureCheckingMode = SignatureValidationStrategies
          .ignoreSignatures();
      return new Builder();
    }


    public final class Builder implements Build {

      /**
       * Build the final decrypted input stream. . This method will start reading the cipherstream
       * until it finds the encrypted plaintext. . If the source data is NOT signed, but a signature
       * is REQUIRED, then this function might even throw. . Signatures are verified AFTER
       * decryption (reading the whole(!) plaintext stream).
       *
       * @param encryptedData An encrypted input stream. Will not be closed.
       *
       * @return Plaintext stream. Signatures are checked the moment EOF is reached.
       *
       * @throws IOException IO is dangerous. Also wraps several GPG exceptions.
       * @throws NoSuchProviderException BC provider is not registered
       */
      @Nonnull
      public InputStream fromEncryptedInputStream(@Nullable InputStream encryptedData)
          throws IOException, NoSuchProviderException {
        if (encryptedData == null) {
          throw new IllegalArgumentException("encryptedData must not be null");
        }

        final DecryptionStreamFactory pgpInputStreamFactory =
            DecryptionStreamFactory.create(
                BuildDecryptionInputStreamAPI.this.keyringConfig,
                BuildDecryptionInputStreamAPI.this.signatureCheckingMode);

        return pgpInputStreamFactory.wrapWithDecryptAndVerify(encryptedData);
      }
    }
  }
}
