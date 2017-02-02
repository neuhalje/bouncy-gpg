package name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting;

import java.util.Arrays;
import java.util.Collection;

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
     * @see DecryptionConfig#getPublicKeyRingStream()
     **/
    public static SignatureValidationStrategy requireAnySignature() {
        return new RequireAnySignatureValidationStrategy();
    }

    /**
     * Require signature from all of the passed keys.
     **/
    public static SignatureValidationStrategy requireSpecificSignature(Collection<Long> signaturesRequiredForTheseKeys) {
        return new RequireSpecificSignatureValidationStrategy(signaturesRequiredForTheseKeys);
    }

    /**
     * Require signature from all of the passed keys.
     **/
    public static SignatureValidationStrategy requireSpecificSignature(Long... keyIds) {
        return new RequireSpecificSignatureValidationStrategy(Arrays.asList(keyIds));
    }

    /**
     * Require signature from a specific key.
     **/
    public static SignatureValidationStrategy requireSpecificSignature(long signaturesRequiredForThisKey) {
        return new RequireSpecificSignatureValidationStrategy(Arrays.asList(signaturesRequiredForThisKey));
    }
}
