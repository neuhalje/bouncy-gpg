package name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting;

/**
 * Defines strategies for signature checking.
 */
public class SignatureValidationStrategies {


    /**
     * Ignore signatures, EVEN BROKEN signatures!
     * <p>
     * Use this at your own peril.
     **/
    public static SignatureValidationStrategy ignoreSignatures() {
        return new IgnoreSignaturesValidationStrategy();
    }

    /**
     * Require any signature for a public key in the keyring.
     *
     * @see DecryptionConfig#getPublicKeyRing()
     **/
    public static SignatureValidationStrategy requireAnySignature() {
        return new RequireAnySignatureValidationStrategy();
    }

    /**
     * Require signature from a specific key.
     **/
    public static SignatureValidationStrategy requireSpecificSignature() {
        return new RequireSpecificSignatureValidationStrategy();
    }

}
