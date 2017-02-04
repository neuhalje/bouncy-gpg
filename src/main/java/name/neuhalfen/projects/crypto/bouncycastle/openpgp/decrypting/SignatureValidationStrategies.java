package name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.shared.PGPUtilities;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKey;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.bouncycastle.openpgp.PGPPublicKeyRingCollection;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

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
    public static SignatureValidationStrategy requireSignatureFromAllKeys(Collection<Long> signaturesRequiredForTheseKeys) {
        return new RequireSpecificSignatureValidationStrategy(signaturesRequiredForTheseKeys);
    }

    /**
     * Require signature from all of the passed keys.
     *
     * @param userIds A list of user IDs (e.g. 'sender@example.com')
     * @throws PGPException No or more than one public key found for a user id
     **/
    public static SignatureValidationStrategy requireSignatureFromAllKeys(PGPPublicKeyRingCollection publicKeyRings, String... userIds) throws PGPException {
        final List<Long> keyIds = new ArrayList<>(userIds.length);

        for (String userId : userIds) {
            final PGPPublicKeyRing pgpPublicKeys = PGPUtilities.extractPublicKeyRingForUserId(userId, publicKeyRings);
            final PGPPublicKey signingKey = PGPUtilities.extractSigningPublicKey(pgpPublicKeys);
            keyIds.add(signingKey.getKeyID());

        }
        return new RequireSpecificSignatureValidationStrategy(keyIds);
    }

    /**
     * Require signature from all of the passed keys.
     **/
    public static SignatureValidationStrategy requireSignatureFromAllKeys(Long... keyIds) {
        return new RequireSpecificSignatureValidationStrategy(Arrays.asList(keyIds));
    }

    /**
     * Require signature from a specific key.
     **/
    public static SignatureValidationStrategy requireSignatureFromAllKeys(long signaturesRequiredForThisKey) {
        return new RequireSpecificSignatureValidationStrategy(Arrays.asList(signaturesRequiredForThisKey));
    }
}
