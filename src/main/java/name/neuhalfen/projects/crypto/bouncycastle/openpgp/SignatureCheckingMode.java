package name.neuhalfen.projects.crypto.bouncycastle.openpgp;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting.DecryptionConfig;

/**
 * Defines modi for signature checking.
 */
public enum SignatureCheckingMode {
    /**
     * Ignore signatures, EVEN BROKEN signatures!
     * <p>
     * Use this at your own peril.
     **/
    IgnoreSignatures,

    /**
     * Require any signature for a public key in the keyring.
     *
     * @see DecryptionConfig#getPublicKeyRing()
     **/
    RequireAnySignature,

    /**
     * Require signature from a specific key.
     * <p>
     * Not implemented yet.
     **/
    RequireSpecificSignature;

    /**
     * @return Iff a signature is required for a document.
     */
    public boolean isRequireSignatureCheck() {
        return this != IgnoreSignatures;
    }
}
