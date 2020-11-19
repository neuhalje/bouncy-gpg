package name.neuhalfen.projects.crypto.bouncycastle.openpgp;

import static java.util.Objects.requireNonNull;

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
import name.neuhalfen.projects.crypto.internal.Preconditions;
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
  public ValidationWithKeySelectionStrategy withConfig(final KeyringConfig keyringConfig) {
    requireNonNull(keyringConfig, "keyringConfig must not be null");

    this.keyringConfig = keyringConfig;
    return new ValidationWithKeySelectionStrategy();
  }

  private KeySelectionStrategy getKeySelectionStrategy() {
    if (this.keySelectionStrategy == null) {
      this.keySelectionStrategy = this.keySelectionStrategyBuilder
          .buildKeySelectionStrategy();
    }
    return this.keySelectionStrategy;
  }

  /**
   * Final build step.
   */
  public interface Build {

    /**
     * <p>
     * Build the final decrypted input stream.
     * </p><p>
     * This method will start reading the cipherstream until it finds the encrypted plaintext.
     * </p><p>
     * If the source data is NOT signed, but a signature is REQUIRED, then this function might
     * throw.
     * </p><p>
     * Signatures are verified AFTER decryption (reading the whole(!) plaintext stream). In this
     * case the returned InputStream will validate the signatures.
     * </p>
     *
     * @param encryptedData An encrypted input stream. <b>Will not be closed</b>.
     *
     * @return Plaintext stream. Signatures are checked the moment EOF is reached.
     *
     * @throws IOException IO is dangerous. Also wraps several GPG exceptions.
     * @throws NoSuchProviderException BC provider is not registered
     */
    @Nonnull
    InputStream fromEncryptedInputStream(final InputStream encryptedData)
        throws IOException, NoSuchProviderException;
  }

  public interface Validation {

    /**
     * <p>Decryption will enforce that the ciphertext has been signed by ALL of the public key ids
     * passed.
     * </p>
     * <p>
     * Given  the following keyring:
     * </p>
     * <pre>{@code
     * $ gpg -k --keyid-format=0xlong
     *
     * ... pub 2048R/0x3DF16BD7C3F280F3 ... uid [ultimate] ...  <signer@example.com>
     * ... sub 2048R/0x54A3DB374F787AB7 ... [S] ... }
     * </pre>
     * <p>
     * To require a valid signature from {@code signer@example.com} with the following keyring, call
     *
     * andRequireSignatureFromAllKeys(0x54A3DB374F787AB7L)
     * </p>
     *
     * @param publicKeyIds A valid signature from ALL of the passed keys is required. Each key
     *     MUST exist in the public keyring.
     *
     * @return the next build step
     */
    @Nonnull
    Build andRequireSignatureFromAllKeys(Long... publicKeyIds);

    /**
     * <p>
     * Decryption will enforce that the ciphertext has been signed by ALL of the public key ids
     * passed.
     * </p>
     *<p>
     * Given  the following keyring:
     *</p>
     * <pre>{@code
     * $ gpg -k --keyid-format=0xlong
     *
     * ... pub 2048R/0x3DF16BD7C3F280F3 ... uid [ultimate] ...  <signer@example.com>
     * ... sub 2048R/0x54A3DB374F787AB7 ... [S] ... }</pre>
     *
     * To require a valid signature from {@code signer@example.com} with the following keyring, call
     *
     * {@code ...andRequireSignatureFromAllKeys("signer@example.com")}
     *
     * @param userIds a valid signature from all of the passed uids is required. The keys MUST
     *     exist
     *     in the public keyring.
     *
     * @return the next build step
     *
     * @throws PGPException error extracting public keys from keyring
     * @throws IOException IO is dangerous. Accessing the keyring might touch the filesystem.
     */
    @Nonnull
    Build andRequireSignatureFromAllKeys(String... userIds)
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

  /**
   * Select keys from keyring.
   */
  public final class ValidationWithKeySelectionStrategy extends ValidationImpl {

    private static final boolean SELECT_UID_BY_E_MAIL_ONLY_DEFAULT = true;
    @Nullable
    private Instant dateOfTimestampVerification;
    @Nullable
    private Boolean selectUidByEMailOnly;
    @Nullable
    private KeySelectionStrategy keySelectionStrategy;


    ValidationWithKeySelectionStrategy() {
      super();
      BuildDecryptionInputStreamAPI.this.keySelectionStrategyBuilder = this;
    }

    /**
     * <p>In order to determine key validity a reference point in time for "now" is needed.
     * The default value is "Instant.now()". If this needs to be overridden, pass the value
     * here. To effectively disable time based key verification pass Instant.MAX (NOT recommended)
     * </p><p>
     * This is not possible in combination with #withKeySelectionStrategy.
     * </p>
     *
     * @param dateOfTimestampVerification reference point in time
     *
     * @return next step in build
     */
    @SuppressWarnings("PMD.LinguisticNaming")
    public Validation setReferenceDateForKeyValidityTo(final Instant dateOfTimestampVerification) {
      Preconditions.checkState(keySelectionStrategy == null,
          "selectUidByAnyUidPart/setReferenceDateForKeyValidityTo cannot "
              + "be used together with 'withKeySelectionStrategy' ");

      requireNonNull(dateOfTimestampVerification,
          "dateOfTimestampVerification must not be null");

      this.dateOfTimestampVerification = dateOfTimestampVerification;
      return this;
    }

    /**
     * <p>The default strategy to search for keys is to *just* search for the email address (the
     * part
     * between &lt; and &gt;).
     * </p>
     * <p>Set this flag to search for any part in the user id.</p>
     *
     * @return next build step
     */
    public Validation selectUidByAnyUidPart() {
      Preconditions.checkState(keySelectionStrategy == null,
          "selectUidByAnyUidPart/setReferenceDateForKeyValidityTo cannot "
              + "be used together with 'withKeySelectionStrategy' ");

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
    public Validation withKeySelectionStrategy(final KeySelectionStrategy strategy) {

      requireNonNull(strategy, "strategy must not be null");

      Preconditions.checkState(
          selectUidByEMailOnly == null && dateOfTimestampVerification == null,
          "selectUidByAnyUidPart/setReferenceDateForKeyValidityTo cannot be used together"
              + " with 'withKeySelectionStrategy' ");

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

  private class ValidationImpl implements Validation {

    @Override
    @Nonnull
    public Build andRequireSignatureFromAllKeys(final Long... publicKeyIds) {
      requireNonNull(publicKeyIds, "publicKeyIds must not be null");
      Preconditions.checkArgument(publicKeyIds.length > 0, "publicKeyIds must not be empty");

      BuildDecryptionInputStreamAPI.this.signatureCheckingMode = SignatureValidationStrategies
          .requireSignatureFromAllKeys(publicKeyIds);
      return new Builder();
    }


    @Override
    @Nonnull
    public Build andRequireSignatureFromAllKeys(final String... userIds)
        throws PGPException, IOException {

      requireNonNull(userIds, "userIds must not be null");
      Preconditions.checkArgument(userIds.length > 0, "userIds must not be empty");

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
      @Override
      @Nonnull
      public InputStream fromEncryptedInputStream(final @Nullable InputStream encryptedData)
          throws IOException, NoSuchProviderException {

        requireNonNull(encryptedData, "encryptedData must not be null");

        final DecryptionStreamFactory pgpInputStreamFactory =
            DecryptionStreamFactory.create(
                BuildDecryptionInputStreamAPI.this.keyringConfig,
                BuildDecryptionInputStreamAPI.this.signatureCheckingMode);

        return pgpInputStreamFactory.wrapWithDecryptAndVerify(encryptedData);
      }
    }
  }
}
