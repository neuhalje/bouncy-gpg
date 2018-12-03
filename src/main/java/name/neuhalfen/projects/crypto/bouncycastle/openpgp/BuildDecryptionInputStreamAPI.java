package name.neuhalfen.projects.crypto.bouncycastle.openpgp;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.time.Instant;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting.DecryptionStreamFactory;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.ByEMailKeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.Rfc4880KeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignatureValidationStrategies;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignatureValidationStrategy;
import org.bouncycastle.openpgp.PGPException;

/**
 * This class implements the builder for decrypting GPG-encrypted streams.
 */
@SuppressWarnings({"PMD.GodClass", "PMD.AtLeastOneConstructor",
    "PMD.AccessorMethodGeneration", "PMD.LawOfDemeter"})
public final class BuildDecryptionInputStreamAPI {

  @Nonnull
  private KeyringConfig keyringConfig;
  @Nonnull
  private SignatureValidationStrategy signatureCheckingMode;


  @SuppressWarnings({"PMD.ImmutableField"})
  private ValidationWithKeySelectionStrategy keySelectionStrategyBuilder;

  /*
   * lazily populated by getKeySelectionStrategy()
   */
  private KeySelectionStrategy keySelectionStrategy;

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


  /**
   * Select keys from keyring.
   */
  public final class ValidationWithKeySelectionStrategy extends ValidationImpl {

    @Nullable
    private Instant dateOfTimestampVerification = null;
    @Nullable
    private Boolean selectUidByEMailOnly = null;
    private static final boolean SELECT_UID_BY_E_MAIL_ONLY_DEFAULT = true;
    @Nullable
    private KeySelectionStrategy keySelectionStrategy = null;


    ValidationWithKeySelectionStrategy() {
      super();
      BuildDecryptionInputStreamAPI.this.keySelectionStrategyBuilder = this;
    }

    /**
     * In order to determine key validity a reference point in time for "now" is needed.
     * The default value is "Instant.now()". If this needs to be overridden, pass the value
     * here. To effectively disable time based key verification pass Instant.MAX (NOT recommended)
     *
     * This is not possible in combination with #withKeySelectionStrategy.
     *
     * @param dateOfTimestampVerification reference point in time
     *
     * @return next step in build
     */
    public Validation setReferenceDateForKeyValidityTo(final Instant dateOfTimestampVerification) {
      if (keySelectionStrategy != null) {
        throw new IllegalStateException(
            "selectUidByAnyUidPart/setReferenceDateForKeyValidityTo cannot be used together with" +
                " 'withKeySelectionStrategy' ");
      }
      if (dateOfTimestampVerification == null) {
        throw new IllegalArgumentException("dateOfTimestampVerification must not be null");
      }
      this.dateOfTimestampVerification = dateOfTimestampVerification;
      return this;
    }

    /**
     * The default strategy to search for keys is to *just* search for the email address (the part
     * between &lt; and &gt;).
     *
     * Set this flag to search for any part in the user id.
     *
     * @return next build step
     */
    public Validation selectUidByAnyUidPart() {
      if (keySelectionStrategy != null) {
        throw new IllegalStateException(
            "selectUidByAnyUidPart/setReferenceDateForKeyValidityTo cannot be used together" +
                " with 'withKeySelectionStrategy' ");
      }
      selectUidByEMailOnly = false;
      return this;
    }

    /**
     * Provide a custom strategy for key selection. Ideally a class derived from
     * Rfc4880KeySelectionStrategy is used.
     *
     * @param strategy the actual instance to use
     *
     * @return next step in builder
     *
     * @see name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.Rfc4880KeySelectionStrategy
     */
    public Validation withKeySelectionStrategy(KeySelectionStrategy strategy) {
      if (strategy == null) {
        throw new IllegalArgumentException("strategy must not be null");
      }
      if (selectUidByEMailOnly != null || dateOfTimestampVerification != null) {
        throw new IllegalStateException(
            "selectUidByAnyUidPart/setReferenceDateForKeyValidityTo cannot be used together"
                + " with 'withKeySelectionStrategy' ");
      }
      this.keySelectionStrategy = strategy;
      return this;
    }


    // Duplicate of BuildEncryptionInputStreamAPI
    @SuppressWarnings({"PMD.OnlyOneReturn"})
    private KeySelectionStrategy buildKeySelectionStrategy() {
      final boolean hasExistingStrategy = this.keySelectionStrategy != null;
      if (hasExistingStrategy) {
        return this.keySelectionStrategy;
      } else {
        if (this.selectUidByEMailOnly == null) {
          this.selectUidByEMailOnly = SELECT_UID_BY_E_MAIL_ONLY_DEFAULT;
        }
        if (this.dateOfTimestampVerification == null) {
          this.dateOfTimestampVerification = Instant.now();
        }

        if (this.selectUidByEMailOnly) {
          return new ByEMailKeySelectionStrategy(this.dateOfTimestampVerification);
        } else {
          return new Rfc4880KeySelectionStrategy(this.dateOfTimestampVerification);
        }
      }
    }
  }

  /**
   * Final build step.
   */
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
          .requireSignatureFromAllUids(getKeySelectionStrategy(), keyringConfig, userIds);
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


  private KeySelectionStrategy getKeySelectionStrategy() {
    if (this.keySelectionStrategy == null) {
      this.keySelectionStrategy = this.keySelectionStrategyBuilder
          .buildKeySelectionStrategy();
    }
    return this.keySelectionStrategy;
  }
}
