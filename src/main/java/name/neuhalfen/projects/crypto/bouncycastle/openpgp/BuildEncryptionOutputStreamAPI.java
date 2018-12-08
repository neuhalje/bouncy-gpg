package name.neuhalfen.projects.crypto.bouncycastle.openpgp;

import static java.util.Objects.requireNonNull;

import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.DefaultPGPAlgorithmSuites;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPAlgorithmSuite;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting.PGPEncryptingStream;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.ByEMailKeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy.PURPOSE;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.Rfc4880KeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;


@SuppressWarnings({"PMD.GodClass", "PMD.AtLeastOneConstructor",
    "PMD.AccessorMethodGeneration", "PMD.LawOfDemeter", "Checkstyle.AbbreviationAsWordInName"})
public final class BuildEncryptionOutputStreamAPI {

  private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory
      .getLogger(BuildEncryptionOutputStreamAPI.class);

  @SuppressWarnings({"PMD.ImmutableField"})
  private WithKeySelectionStrategy keySelectionStrategyBuilder;

  /*
   * lazily populated by getKeySelectionStrategy()
   */
  private KeySelectionStrategy keySelectionStrategy;

  private OutputStream sinkForEncryptedData;
  private KeyringConfig encryptionConfig;
  private PGPAlgorithmSuite algorithmSuite;

  @Nullable
  private String signWith;
  private Set<PGPPublicKey> recipients;
  private boolean armorOutput;

  // Signature


  /**
   * <p>Use the passed keyring config for the crypto operations. The KeyringConfig wraps the
   * public- and private keyrings.
   * </p><p>
   * Generally the best KeyringConfig variant to use is the {@link InMemoryKeyring} which can be
   * created by calling {@link KeyringConfigs#forGpgExportedKeys(KeyringConfigCallback)}. </p>
   *
   * @param encryptionConfig the keyring config.
   *
   * @return the next step in the builder
   *
   * @throws IOException bouncy castle uses IO
   * @throws PGPException errors in the config
   * @see name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfigs
   * @see name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.InMemoryKeyring
   */
  @SuppressWarnings("PMD.AccessorClassGeneration")
  public WithKeySelectionStrategy withConfig(final KeyringConfig encryptionConfig)
      throws IOException, PGPException {
    requireNonNull(encryptionConfig, "encryptionConfig must not be null");
    requireNonNull(encryptionConfig.getKeyFingerPrintCalculator(),
        "encryptionConfig.getKeyFingerPrintCalculator() must not be null");
    requireNonNull(encryptionConfig.getPublicKeyRings(),
        "encryptionConfig.getPublicKeyRings() must not be null");

    this.encryptionConfig = encryptionConfig;
    return new WithKeySelectionStrategy();
  }

  private KeySelectionStrategy getKeySelectionStrategy() {
    if (this.keySelectionStrategy == null) {
      this.keySelectionStrategy = this.keySelectionStrategyBuilder
          .buildKeySelectionStrategy();
    }
    return this.keySelectionStrategy;
  }


  public interface Build {

    OutputStream andWriteTo(OutputStream sinkForEncryptedData)
        throws PGPException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException, IOException;
  }


  public interface WithAlgorithmSuite {

    To withDefaultAlgorithms();

    To withStrongAlgorithms();

    To withAlgorithms(PGPAlgorithmSuite algorithmSuite);

    @SuppressWarnings("PMD.ShortClassName")
    interface To {

      SignWith toRecipient(String recipient) throws PGPException;

      SignWith toRecipients(String... recipients) throws PGPException;

      interface SignWith {

        Armor andSignWith(String userId) throws IOException, PGPException;

        Armor andDoNotSign();

        interface Armor {

          Build binaryOutput();

          Build armorAsciiOutput();
        }
      }
    }
  }

  /**
   * Combined step for key- and algorithm selection.
   */
  public final class WithKeySelectionStrategy extends WithAlgorithmSuiteImpl {

    private static final boolean SELECT_UID_BY_E_MAIL_ONLY_DEFAULT = true;

    @Nullable
    private Instant dateOfTimestampVerification;

    @Nullable
    @SuppressWarnings({"PMD.LinguisticNaming"})
    private Boolean selectUidByEMailOnly;

    @Nullable
    private KeySelectionStrategy keySelectionStrategy;

    private WithKeySelectionStrategy() {
      super();
      BuildEncryptionOutputStreamAPI.this.keySelectionStrategyBuilder = this;
    }

    /**
     * <p>
     * Normally keys are only searched by e-mail (between &lt; and &gt;). Calling
     * selectUidByAnyUidPart() will search everywhere.
     * </p><p>
     * E.g. given the uid 'Juliet Capulet &lt;juliet@example.org&gt;' a search normally would
     * look for the e-mail 'juliet@example.org'. E.g. searching for 'juliet' would be found,
     * searching for 'Capulet' would not be found.
     * </p>
     * <p>
     * After calling selectUidByAnyUidPart() the key will also be found by searching for 'Capulet'
     * </p>
     *
     * @return next step
     */
    public WithKeySelectionStrategy selectUidByAnyUidPart() {
      if (keySelectionStrategy != null) {
        throw new IllegalStateException(
            "selectUidByAnyUidPart/setReferenceDateForKeyValidityTo cannot be used together " +
                "with 'withKeySelectionStrategy' ");
      }
      selectUidByEMailOnly = false;
      return this;
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
    @SuppressWarnings("PMD.LinguisticNaming")
    public WithAlgorithmSuite setReferenceDateForKeyValidityTo(
        final Instant dateOfTimestampVerification) {

      if (keySelectionStrategy != null) {
        throw new IllegalStateException(
            "selectUidByAnyUidPart/setReferenceDateForKeyValidityTo cannot be used together " +
                "with 'withKeySelectionStrategy' ");
      }
      requireNonNull(dateOfTimestampVerification, "dateOfTimestampVerification must not be null");

      this.dateOfTimestampVerification = dateOfTimestampVerification;
      LOGGER.trace("WithKeySelectionStrategy: setReferenceDateForKeyValidityTo {}",
          dateOfTimestampVerification);
      return this;
    }

    /**
     * The default strategy to search for keys is to *just* search for the email address (the part
     * between &lt; and &gt;).
     *
     * Set this flag to search for any part in the user id.
     *
     * @param strategy instance to use
     *
     * @return next build step
     */
    public WithAlgorithmSuite withKeySelectionStrategy(final KeySelectionStrategy strategy) {
      requireNonNull(strategy, "strategy must not be null");

      if (selectUidByEMailOnly != null || dateOfTimestampVerification != null) {
        throw new IllegalStateException(
            "selectUidByAnyUidPart/setReferenceDateForKeyValidityTo cannot be used together" +
                " with 'withKeySelectionStrategy' ");
      }
      this.keySelectionStrategy = strategy;
      LOGGER.trace("WithKeySelectionStrategy: override strategy to {}",
          strategy.getClass().toGenericString());
      return this;
    }


    // Duplicate of BuildDecryptionInputStreamAPI
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

  private class WithAlgorithmSuiteImpl implements WithAlgorithmSuite {

    @Override
    public To withDefaultAlgorithms() {
      BuildEncryptionOutputStreamAPI.this.algorithmSuite = DefaultPGPAlgorithmSuites
          .defaultSuiteForGnuPG();
      LOGGER
          .trace("use algorithms {}",
              BuildEncryptionOutputStreamAPI.this.algorithmSuite.toString());
      return new ToImpl();
    }

    @Override
    public To withStrongAlgorithms() {
      BuildEncryptionOutputStreamAPI.this.algorithmSuite = DefaultPGPAlgorithmSuites.strongSuite();
      LOGGER
          .trace("use algorithms {}",
              BuildEncryptionOutputStreamAPI.this.algorithmSuite.toString());
      return new ToImpl();
    }

    @Override
    public To withAlgorithms(PGPAlgorithmSuite algorithmSuite) {
      if (algorithmSuite == null) {
        throw new IllegalArgumentException("algorithmSuite must not be null");
      }
      BuildEncryptionOutputStreamAPI.this.algorithmSuite = algorithmSuite;
      LOGGER
          .trace("use algorithms {}",
              BuildEncryptionOutputStreamAPI.this.algorithmSuite.toString());
      return new ToImpl();
    }


    @SuppressWarnings("PMD.ShortClassName")
    final class ToImpl implements To {

      private PGPPublicKey extractValidKey(final String recipient) throws PGPException {
        if (recipient == null || recipient.isEmpty()) {
          throw new IllegalArgumentException("recipient must be a string");
        }
        try {
          final PGPPublicKey recipientEncryptionKey = getKeySelectionStrategy()
              .selectPublicKey(PURPOSE.FOR_ENCRYPTION, recipient, encryptionConfig);

          if (recipientEncryptionKey == null) {
            throw new PGPException(
                "No (suitable) public key for encryption to " + recipient + " found");
          }

          LOGGER.trace("encrypt to recipient {} using key 0x{}", recipient,
              Long.toHexString(recipientEncryptionKey.getKeyID()));
          return recipientEncryptionKey;
        } catch (IOException e) {
          throw new PGPException("Failed to load keys", e);
        }

      }

      @Override
      public SignWith toRecipient(final String recipient) throws PGPException {

        BuildEncryptionOutputStreamAPI.this.recipients = new HashSet<>();
        BuildEncryptionOutputStreamAPI.this.recipients.add(extractValidKey(recipient));

        return new SignWithImpl();
      }

      @Override
      public SignWith toRecipients(String... recipients) throws PGPException {
        BuildEncryptionOutputStreamAPI.this.recipients = new HashSet<>();

        for (final String recipient : recipients) {
          BuildEncryptionOutputStreamAPI.this.recipients.add(extractValidKey(recipient));
        }

        return new SignWithImpl();
      }


      final class SignWithImpl implements SignWith {

        @Override
        public Armor andSignWith(String userId) throws IOException, PGPException {

          if (encryptionConfig.getSecretKeyRings() == null) {
            throw new IllegalArgumentException(
                "encryptionConfig.getSecretKeyRings() must not be null");
          }

          final PGPPublicKey signingKeyPubKey = getKeySelectionStrategy()
              .selectPublicKey(PURPOSE.FOR_SIGNING, userId, encryptionConfig);

          if (signingKeyPubKey == null) {
            throw new PGPException(
                "No (suitable) public key for signing with '" + userId + "' found");
          }

          final PGPSecretKey signingKey = encryptionConfig.getSecretKeyRings()
              .getSecretKey(signingKeyPubKey.getKeyID());
          if (signingKey == null) {
            throw new PGPException(
                "No (suitable) secret key for signing with " + userId
                    + " found (public key exists!)");
          }

          BuildEncryptionOutputStreamAPI.this.signWith = userId;
          LOGGER.trace("sign with {}", BuildEncryptionOutputStreamAPI.this.signWith);
          return new ArmorImpl();
        }

        @Override
        @SuppressWarnings("PMD.NullAssignment")
        public Armor andDoNotSign() {
          BuildEncryptionOutputStreamAPI.this.signWith = null;
          LOGGER.trace("do not sign ");
          return new ArmorImpl();
        }


        public final class ArmorImpl implements Armor {

          @Override
          public Build binaryOutput() {
            BuildEncryptionOutputStreamAPI.this.armorOutput = false;
            LOGGER.trace("binary output");
            return new Builder();
          }

          @Override
          public Build armorAsciiOutput() {
            BuildEncryptionOutputStreamAPI.this.armorOutput = true;
            LOGGER.trace("ascii armor output");
            return new Builder();
          }


          public final class Builder implements Build {

            @Override
            public OutputStream andWriteTo(OutputStream sinkForEncryptedData)
                throws PGPException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
              BuildEncryptionOutputStreamAPI.this.sinkForEncryptedData = sinkForEncryptedData;
              return PGPEncryptingStream.create(
                  BuildEncryptionOutputStreamAPI.this.encryptionConfig,
                  BuildEncryptionOutputStreamAPI.this.algorithmSuite,
                  BuildEncryptionOutputStreamAPI.this.signWith,
                  BuildEncryptionOutputStreamAPI.this.sinkForEncryptedData,
                  getKeySelectionStrategy(),
                  BuildEncryptionOutputStreamAPI.this.armorOutput,
                  BuildEncryptionOutputStreamAPI.this.recipients);

            }
          }
        }
      }
    }
  }
}