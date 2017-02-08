package name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.KeyringConfig;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

import java.io.IOException;


public class EncryptionConfig {
    private final String signatureSecretKeyId;
    private final String encryptionPublicKeyId;
    private final int pgpHashAlgorithmCode;
    private final int pgpSymmetricEncryptionAlgorithmCode;
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
                            int pgpSymmetricEncryptionAlgorithmCode,
                            KeyringConfig keyringConfig) {
        this.keyringConfig = keyringConfig;
        this.signatureSecretKeyId = signatureSecretKeyId;
        this.encryptionPublicKeyId = encryptionPublicKeyId;
        this.pgpHashAlgorithmCode = pgpHashAlgorithmCode;
        this.pgpSymmetricEncryptionAlgorithmCode = pgpSymmetricEncryptionAlgorithmCode;
    }

    @Override
    public String toString() {
        final StringBuilder sb = new StringBuilder("EncryptionConfig{");
        sb.append("signatureSecretKeyId='").append(signatureSecretKeyId).append('\'');
        sb.append(", encryptionPublicKeyId='").append(encryptionPublicKeyId).append('\'');
        sb.append(", pgpHashAlgorithmCode=").append(pgpHashAlgorithmCode);
        sb.append(", pgpSymmetricEncryptionAlgorithmCode=").append(pgpSymmetricEncryptionAlgorithmCode);
        sb.append(", keyringConfig='").append(keyringConfig.toString()).append('\'');
        sb.append('}');
        return sb.toString();
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

    public int getPgpSymmetricEncryptionAlgorithmCode() {
        return pgpSymmetricEncryptionAlgorithmCode;
    }


    public char[] signingKeyPassphrase(long keyID) {
        return keyringConfig.decryptionSecretKeyPassphraseForSecretKeyId(keyID);
    }

    public KeyringConfig getConfig() {
        return keyringConfig;
    }
}
