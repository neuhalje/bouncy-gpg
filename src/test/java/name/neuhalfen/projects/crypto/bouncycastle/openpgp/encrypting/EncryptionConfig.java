package name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting;


import java.io.IOException;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;


/**
 * TODO: This class now only serves as a vehicle to old test drivers and should be factored into
 * oblivion
 */
public class EncryptionConfig {

  private final String signatureSecretKeyId;
  private final String encryptionPublicKeyId;
  private final int pgpHashAlgorithmCode;
  private final KeyringConfig keyringConfig;


  public PGPPublicKeyRingCollection getPublicKeyRings() throws IOException, PGPException {

    return keyringConfig.getPublicKeyRings();
  }

  public PGPSecretKeyRingCollection getSecretKeyRings() throws IOException, PGPException {

    return keyringConfig.getSecretKeyRings();
  }


  public EncryptionConfig(String signatureSecretKeyId,
      String encryptionPublicKeyId,
      int pgpHashAlgorithmCode,
      KeyringConfig keyringConfig) {
    this.keyringConfig = keyringConfig;
    this.signatureSecretKeyId = signatureSecretKeyId;
    this.encryptionPublicKeyId = encryptionPublicKeyId;
    this.pgpHashAlgorithmCode = pgpHashAlgorithmCode;
  }


  public String getSignatureSecretKeyId() {
    return signatureSecretKeyId;
  }

  public String getEncryptionPublicKeyId() {
    return encryptionPublicKeyId;
  }

  public int getPgpHashAlgorithmCode() {
    return pgpHashAlgorithmCode;
  }


  public KeyringConfig getConfig() {
    return keyringConfig;
  }
}
