package name.neuhalfen.projects.crypto.bouncycastle.openpgp;

import java.io.IOException;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.DefaultPGPAlgorithmSuites;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPAlgorithmSuite;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting.PGPEncryptingStream;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.PGPUtilities;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;


public final class BuildEncryptionOutputStreamAPI {

  private OutputStream sinkForEncryptedData;
  private KeyringConfig encryptionConfig;
  private PGPAlgorithmSuite algorithmSuite;
  @Nullable
  private String signWith;
  private PGPPublicKey recipient;
  private boolean armorOutput;
  BuildEncryptionOutputStreamAPI() {
  }

  // Signature

  public WithAlgorithmSuite withConfig(KeyringConfig encryptionConfig)
      throws IOException, PGPException {
    if (encryptionConfig == null) {
      throw new NullPointerException("encryptionConfig must not be null");
    }

    if (encryptionConfig.getKeyFingerPrintCalculator() == null) {
      throw new NullPointerException(
          "encryptionConfig.getKeyFingerPrintCalculator() must not be null");
    }

    if (encryptionConfig.getPublicKeyRings() == null) {
      throw new NullPointerException("encryptionConfig.getPublicKeyRings() must not be null");
    }

    BuildEncryptionOutputStreamAPI.this.encryptionConfig = encryptionConfig;
    return new WithAlgorithmSuite();
  }


  public interface Build {

    OutputStream andWriteTo(OutputStream sinkForEncryptedData)
        throws PGPException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException, IOException;
  }

  public final class WithAlgorithmSuite {

    public To withDefaultAlgorithms() {
      BuildEncryptionOutputStreamAPI.this.algorithmSuite = DefaultPGPAlgorithmSuites
          .defaultSuiteForGnuPG();
      return new To();
    }

    public To withStrongAlgorithms() {
      BuildEncryptionOutputStreamAPI.this.algorithmSuite = DefaultPGPAlgorithmSuites.strongSuite();
      return new To();
    }

    public To withAlgorithms(PGPAlgorithmSuite algorithmSuite) {
      if (algorithmSuite == null) {
        throw new NullPointerException("algorithmSuite must not be null");
      }
      BuildEncryptionOutputStreamAPI.this.algorithmSuite = algorithmSuite;
      return new To();
    }


    public final class To {

      public SignWith toRecipient(String recipient) throws IOException, PGPException {

        final PGPPublicKeyRing publicKeyRing = PGPUtilities
            .extractPublicKeyRingForUserId(recipient, encryptionConfig.getPublicKeyRings());
        if (publicKeyRing == null) {
          throw new PGPException(
              "No (suitable) public key for encryption to " + recipient + " found");
        }

        final PGPPublicKey recipientEncryptionKey = PGPUtilities.getEncryptionKey(publicKeyRing);

        if (recipientEncryptionKey == null) {
          throw new PGPException(
              "No (suitable) public key for encryption to " + recipient + " found");
        }
        BuildEncryptionOutputStreamAPI.this.recipient = recipientEncryptionKey;
        return new SignWith();
      }


      public final class SignWith {

        public Armor andSignWith(String userId) throws IOException, PGPException {

          if (encryptionConfig.getSecretKeyRings() == null) {
            throw new NullPointerException("encryptionConfig.getSecretKeyRings() must not be null");
          }
          BuildEncryptionOutputStreamAPI.this.signWith = userId;
          return new Armor();
        }

        public Armor andDoNotSign() {
          BuildEncryptionOutputStreamAPI.this.signWith = null;
          return new Armor();
        }


        public final class Armor {

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