package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.keyrings;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.callbacks.KeyringConfigCallback;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;

import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

import static java.util.Collections.EMPTY_LIST;

public final class InMemoryKeyring implements KeyringConfig {

    @Nonnull
    private final KeyringConfigCallback callback;
    @Nonnull
    private PGPPublicKeyRingCollection publicKeyRings;
    @Nonnull
    private PGPSecretKeyRingCollection secretKeyRings;

    private final KeyFingerPrintCalculator keyFingerPrintCalculator = new BcKeyFingerprintCalculator();

    InMemoryKeyring(final KeyringConfigCallback callback) throws IOException, PGPException {
        if (callback == null) {
            throw new NullPointerException("callback must not be null");
        }
        this.callback = callback;
        this.publicKeyRings = new PGPPublicKeyRingCollection(EMPTY_LIST);
        this.secretKeyRings = new PGPSecretKeyRingCollection(EMPTY_LIST);
    }

    /**
     * Add a new public keyring to the public keyrings.
     * .
     * Can read the result of "gpg --export" and "gpg --export -a keyid"
     * .
     * E.g.  "gpg --export -a keyid":
     * addPublicKey("-----BEGIN PGP PUBLIC KEY BLOCK----- ....".getBytes("US-ASCII")
     *
     * @param encodedPublicKey the key ascii armored or binary
     * @throws IOException  IO is dangerous
     * @throws PGPException E.g. this is nor a valid key
     */
    public void addPublicKey(byte[] encodedPublicKey) throws IOException, PGPException {

        if (encodedPublicKey == null) {
            throw new NullPointerException("encodedPublicKey must not be null");
        }

        try (
                final InputStream raw = new ByteArrayInputStream(encodedPublicKey);
                final InputStream decoded = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(raw)
        ) {
            PGPPublicKeyRing pgpPub = new PGPPublicKeyRing(decoded, getKeyFingerPrintCalculator());
            this.publicKeyRings = PGPPublicKeyRingCollection.addPublicKeyRing(this.publicKeyRings, pgpPub);
        }
    }


    /**
     * Add a new secret keyring to the public keyrings.
     * .
     * Can read the result of "gpg --export" and "gpg --export -a keyid"
     * .
     * E.g. "gpg --export-secret-key -a keyid":
     * addSecretKey("-----BEGIN PGP PRIVATE KEY BLOCK----- ....".getBytes("US-ASCII")
     * <p>
     * The password is queried via the callback (decryptionSecretKeyPassphraseForSecretKeyId).
     *
     * @param encodedPrivateKey the key ascii armored or binary
     * @throws IOException  IO is dangerous
     * @throws PGPException E.g. this is nor a valid key
     */
    public void addSecretKey(byte[] encodedPrivateKey) throws IOException, PGPException {

        if (encodedPrivateKey == null) {
            throw new NullPointerException("encodedPrivateKey must not be null");
        }

        try (
                final InputStream raw = new ByteArrayInputStream(encodedPrivateKey);
                final InputStream decoded = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(raw)
        ) {
            PGPSecretKeyRing pgpPRivate = new PGPSecretKeyRing(decoded, getKeyFingerPrintCalculator());
            this.secretKeyRings = PGPSecretKeyRingCollection.addSecretKeyRing(this.secretKeyRings, pgpPRivate);
        }
    }

    @Nonnull
    @Override
    public PGPPublicKeyRingCollection getPublicKeyRings() throws IOException, PGPException {
        return this.publicKeyRings;
    }

    @Nonnull
    @Override
    public PGPSecretKeyRingCollection getSecretKeyRings() throws IOException, PGPException {
        return this.secretKeyRings;
    }

    @Nullable
    @Override
    public char[] decryptionSecretKeyPassphraseForSecretKeyId(long keyID) {
        return callback.decryptionSecretKeyPassphraseForSecretKeyId(keyID);
    }

    @Override
    public KeyFingerPrintCalculator getKeyFingerPrintCalculator() {
        return keyFingerPrintCalculator;
    }
}
