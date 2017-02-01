package name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting;


import org.bouncycastle.openpgp.*;

import java.io.IOException;
import java.security.SignatureException;
import java.util.Map;

class RequireAnySignatureValidationStrategy implements SignatureValidationStrategy {
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(RequireAnySignatureValidationStrategy.class);

    @Override
    public void validateSignatures(PGPObjectFactory factory, Map<Long, PGPOnePassSignature> onePassSignatures) throws
            SignatureException, PGPException, IOException {
        // verify the signature
        final PGPSignatureList signatureList = (PGPSignatureList) factory.nextObject();

        if (signatureList == null || signatureList.isEmpty()) {
            throw new PGPException("No signatures found!");
        }

        boolean successfullyVerified = false;

        for (PGPSignature messageSignature : signatureList) {
            PGPOnePassSignature ops = onePassSignatures.get(messageSignature.getKeyID());

            if (ops != null) {
                final boolean isThisSignatureGood = ops.verify(messageSignature);

                LOGGER.debug("{} validated signature with key {}", isThisSignatureGood ? "Successfully" : "Failed to", messageSignature.getKeyID());
                successfullyVerified |= isThisSignatureGood;
            } else {
                LOGGER.debug("Could not validated signature with key {} because we have no matching public key", messageSignature.getKeyID());
            }
        }

        if (successfullyVerified) {
            LOGGER.debug("Signature verification success");
        } else {
            throw new SignatureException("Signature verification failed!");
        }
    }

    @Override
    public boolean isRequireSignatureCheck() {
        return true;
    }
}
