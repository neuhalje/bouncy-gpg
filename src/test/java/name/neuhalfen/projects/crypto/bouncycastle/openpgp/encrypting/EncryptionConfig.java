package name.neuhalfen.projects.crypto.bouncycastle.openpgp.encrypting;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PGPHashAlgorithms;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeySelectionStrategy.PURPOSE;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.Rfc4880KeySelectionStrategy;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings.KeyringConfig;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;

import java.io.IOException;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;


/**
 * TODO: This class now only serves as a vehicle to old test drivers and should be factored into
 * oblivion
 */
public class EncryptionConfig {

    private final String signatureSecretKeyId;
    private final String encryptionPublicKeyId;
    private final PGPHashAlgorithms pgpHashAlgorithmCode;
    private final KeyringConfig keyringConfig;

    private final KeySelectionStrategy keySelectionStrategy = new Rfc4880KeySelectionStrategy(
            Instant.MAX);

    public EncryptionConfig(String signatureSecretKeyId,
                            String encryptionPublicKeyId,
                            PGPHashAlgorithms pgpHashAlgorithmCode,
                            KeyringConfig keyringConfig) {
        this.keyringConfig = keyringConfig;
        this.signatureSecretKeyId = signatureSecretKeyId;
        this.encryptionPublicKeyId = encryptionPublicKeyId;
        this.pgpHashAlgorithmCode = pgpHashAlgorithmCode;
    }

    public PGPPublicKeyRingCollection getPublicKeyRings() throws IOException, PGPException {

        return keyringConfig.getPublicKeyRings();
    }

    public PGPSecretKeyRingCollection getSecretKeyRings() throws IOException, PGPException {

        return keyringConfig.getSecretKeyRings();
    }

    public String getSignatureSecretKeyId() {
        return signatureSecretKeyId;
    }

    public String getEncryptionPublicKeyId() {
        return encryptionPublicKeyId;
    }

    public int getPgpHashAlgorithmCode() {
        return pgpHashAlgorithmCode.getAlgorithmId();
    }


    public KeyringConfig getConfig() {
        return keyringConfig;
    }

    public Set<PGPPublicKey> getEncryptionPublicKeys() throws PGPException, IOException {
        Set<PGPPublicKey> keys = new HashSet<>();
        keys.add(keySelectionStrategy
                .selectPublicKey(PURPOSE.FOR_ENCRYPTION, getEncryptionPublicKeyId(), keyringConfig));

        return keys;
    }

    public Set<PGPPublicKey> getEncryptionPublicKeysNoValidation() throws IOException, PGPException {
        Set<PGPPublicKey> keys = new HashSet<>();
        keys.add(
                keyringConfig.getPublicKeyRings().getKeyRings(getEncryptionPublicKeyId(), true, true).next()
                        .getPublicKey());

        return keys;
    }
}
