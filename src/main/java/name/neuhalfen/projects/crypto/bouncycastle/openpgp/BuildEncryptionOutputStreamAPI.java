package name.neuhalfen.projects.crypto.bouncycastle.openpgp;

import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.time.Instant;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.DefaultPGPAlgorithmSuites;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPAlgorithmSuite;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting.PGPEncryptingStream;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy.PURPOSE;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.Rfc4880KeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPSecretKey;


@SuppressWarnings({"PMD.AtLeastOneConstructor", "PMD.AccessorMethodGeneration", "PMD.LawOfDemeter"})
public final class BuildEncryptionOutputStreamAPI {

  private OutputStream sinkForEncryptedData;
  private KeyringConfig encryptionConfig;
  private PGPAlgorithmSuite algorithmSuite;

  private KeySelectionStrategy keySelectionStrategy;

  @Nullable
  private String signWith;
  private PGPPublicKey recipient;
  private boolean armorOutput;

  // Signature


  @SuppressWarnings("PMD.AccessorClassGeneration")
  public WithKeySelectionStrategy withConfig(KeyringConfig encryptionConfig)
      throws IOException, PGPException {
    if (encryptionConfig == null) {
      throw new IllegalArgumentException("encryptionConfig must not be null");
    }

    if (encryptionConfig.getKeyFingerPrintCalculator() == null) {
      throw new IllegalArgumentException(
          "encryptionConfig.getKeyFingerPrintCalculator() must not be null");
    }

    if (encryptionConfig.getPublicKeyRings() == null) {
      throw new IllegalArgumentException("encryptionConfig.getPublicKeyRings() must not be null");
    }

    BuildEncryptionOutputStreamAPI.this.encryptionConfig = encryptionConfig;
    return new WithKeySelectionStrategy();
  }

  public final class WithKeySelectionStrategy extends WithAlgorithmSuiteImpl {

    private WithKeySelectionStrategy() {
      super();
      BuildEncryptionOutputStreamAPI.this.keySelectionStrategy = new Rfc4880KeySelectionStrategy(
          Instant.now());
    }

    public WithAlgorithmSuite setReferenceDateForKeyValidityTo(
        Instant dateOfTimestampVerification) {
      if (dateOfTimestampVerification == null) {
        throw new IllegalArgumentException("dateOfTimestampVerification must not be null");
      }
      BuildEncryptionOutputStreamAPI.this.keySelectionStrategy = new Rfc4880KeySelectionStrategy(
          Instant.now());
      return new WithAlgorithmSuiteImpl();
    }

    public WithAlgorithmSuite withKeySelectionStrategy(KeySelectionStrategy strategy) {
      if (strategy == null) {
        throw new IllegalArgumentException("strategy must not be null");
      }
      BuildEncryptionOutputStreamAPI.this.keySelectionStrategy = strategy;
      return new WithAlgorithmSuiteImpl();
    }
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


  private class WithAlgorithmSuiteImpl implements WithAlgorithmSuite {

    public To withDefaultAlgorithms() {
      BuildEncryptionOutputStreamAPI.this.algorithmSuite = DefaultPGPAlgorithmSuites
          .defaultSuiteForGnuPG();
      return new ToImpl();
    }

    public To withStrongAlgorithms() {
      BuildEncryptionOutputStreamAPI.this.algorithmSuite = DefaultPGPAlgorithmSuites.strongSuite();
      return new ToImpl();
    }

    public To withAlgorithms(PGPAlgorithmSuite algorithmSuite) {
      if (algorithmSuite == null) {
        throw new IllegalArgumentException("algorithmSuite must not be null");
      }
      BuildEncryptionOutputStreamAPI.this.algorithmSuite = algorithmSuite;
      return new ToImpl();
    }


    @SuppressWarnings("PMD.ShortClassName")
    final class ToImpl implements To {

      @Override
      public SignWith toRecipient(String recipient) throws PGPException {
        if (recipient == null || recipient.isEmpty()) {
          throw new IllegalArgumentException("recipient must be a string");
        }
        try {
          final PGPPublicKey recipientEncryptionKey = keySelectionStrategy
              .selectPublicKey(PURPOSE.FOR_ENCRYPTION, recipient, encryptionConfig);

          if (recipientEncryptionKey == null) {
            throw new PGPException(
                "No (suitable) public key for encryption to " + recipient + " found");
          }
          BuildEncryptionOutputStreamAPI.this.recipient = recipientEncryptionKey;
          return new SignWithImpl();
        } catch (IOException e) {
          throw new PGPException("Failed to load keys", e);
        }
      }


      final class SignWithImpl implements SignWith {

        public Armor andSignWith(String userId) throws IOException, PGPException {

          if (encryptionConfig.getSecretKeyRings() == null) {
            throw new IllegalArgumentException(
                "encryptionConfig.getSecretKeyRings() must not be null");
          }

          final PGPPublicKey signingKeyPubKey = keySelectionStrategy
              .selectPublicKey(PURPOSE.FOR_SIGNING, userId, encryptionConfig);

          if (signingKeyPubKey == null) {
            throw new PGPException(
                "No (suitable) public key for signing with '" + userId + "' found");
          }

          PGPSecretKey signingKey = encryptionConfig.getSecretKeyRings()
              .getSecretKey(signingKeyPubKey.getKeyID());
          if (signingKey == null) {
            throw new PGPException(
                "No (suitable) secret key for signing with " + recipient
                    + " found (public key exists!)");
          }

          BuildEncryptionOutputStreamAPI.this.signWith = userId;
          return new ArmorImpl();
        }

        @SuppressWarnings("PMD.NullAssignment")
        public Armor andDoNotSign() {
          BuildEncryptionOutputStreamAPI.this.signWith = null;
          return new ArmorImpl();
        }


        public final class ArmorImpl implements Armor {

          public Build binaryOutput() {
            BuildEncryptionOutputStreamAPI.this.armorOutput = false;
            return new Builder();
          }

          public Build armorAsciiOutput() {
            BuildEncryptionOutputStreamAPI.this.armorOutput = true;
            return new Builder();
          }


          public final class Builder implements Build {

            public OutputStream andWriteTo(OutputStream sinkForEncryptedData)
                throws PGPException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException, IOException {
              BuildEncryptionOutputStreamAPI.this.sinkForEncryptedData = sinkForEncryptedData;
              final OutputStream outputStream = PGPEncryptingStream.create(
                  BuildEncryptionOutputStreamAPI.this.encryptionConfig,
                  BuildEncryptionOutputStreamAPI.this.algorithmSuite,
                  BuildEncryptionOutputStreamAPI.this.signWith,
                  BuildEncryptionOutputStreamAPI.this.sinkForEncryptedData,
                  BuildEncryptionOutputStreamAPI.this.keySelectionStrategy,
                  BuildEncryptionOutputStreamAPI.this.armorOutput,
                  BuildEncryptionOutputStreamAPI.this.recipient);
              return outputStream;

            }
          }
        }
      }
    }
  }
}