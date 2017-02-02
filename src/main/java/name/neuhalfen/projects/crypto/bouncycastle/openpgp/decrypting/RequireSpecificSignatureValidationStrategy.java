package name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting;


import org.bouncycastle.openpgp.*;

import java.io.IOException;
import java.security.SignatureException;
import java.util.Collection;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

class RequireSpecificSignatureValidationStrategy implements SignatureValidationStrategy {
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(RequireSpecificSignatureValidationStrategy.class);

    private final Set<Long> signaturesRequiredForTheseKeys;

    /**
     * @param signaturesRequiredForTheseKeys Signatures for all keys are needed
     */
    RequireSpecificSignatureValidationStrategy(Collection<Long> signaturesRequiredForTheseKeys) {
        this.signaturesRequiredForTheseKeys = new HashSet<>(signaturesRequiredForTheseKeys);
    }

    @Override
    public void validateSignatures(PGPObjectFactory factory, Map<Long, PGPOnePassSignature> onePassSignatures) throws
            SignatureException, PGPException, IOException {


        // verify the signature
        final PGPSignatureList signatureList = (PGPSignatureList) factory.nextObject();

        if (signatureList == null || signatureList.isEmpty()) {
            // This statement is not reached in normal flow
            // because decryption errs first when it does not find
            // the one pass signature before the data object.
            throw new PGPException("No signatures found!");
        }

        final Set<Long> signaturesRequiredForTheseKeysCheckList = new HashSet<>(signaturesRequiredForTheseKeys);

        for (PGPSignature messageSignature : signatureList) {
            final PGPOnePassSignature ops = onePassSignatures.get(messageSignature.getKeyID());

            if (ops != null) {
                final boolean isThisSignatureGood = ops.verify(messageSignature);

                LOGGER.debug("{} validated signature with key 0x{}", isThisSignatureGood ? "Successfully" : "Failed to", Long.toHexString(messageSignature.getKeyID()));
                if (isThisSignatureGood) {
                    signaturesRequiredForTheseKeysCheckList.remove(messageSignature.getKeyID());
                }
            } else {
                LOGGER.debug("Could not validated signature with key 0x{} because we have no matching public key", Long.toHexString(messageSignature.getKeyID()));
            }
        }

        final boolean successfullyVerified = signaturesRequiredForTheseKeysCheckList.isEmpty();

        if (successfullyVerified) {
            LOGGER.debug("Signature verification success");
        } else {
            final StringBuilder missingSignatures = new StringBuilder();
            for (Long key : signaturesRequiredForTheseKeysCheckList) {
                if (missingSignatures.length() != 0) {
                    missingSignatures.append(", ");
                }
                missingSignatures.append("0x");
                missingSignatures.append(Long.toHexString(key));
            }
            throw new SignatureException("Signature verification failed! The following signatures (from keys) could not be verified: " + missingSignatures.toString());
        }
    }

    @Override
    public boolean isRequireSignatureCheck() {
        return true;
    }
}
