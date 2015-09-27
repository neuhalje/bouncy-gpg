package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting;


import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.shared.PGPUtilities;
import org.bouncycastle.openpgp.*;

import java.util.Iterator;

/**
 * collection of non-member methods for encryption
 */
class Helpers {

    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(EncryptWithOpenPGP.class);

    /**
     * Extracts the first secret signing key for UID {@code signatureUid} suitable for signature generation from a key
     * ring collection {@code secretKeyRings}.
     *
     * @param pgpSec        a Collection of secret key rings
     * @param signingKeyUid signature Key uid to search for
     * @return the first secret key for signatureUid suitable for signatures
     * @throws PGPException if no key ring or key with that Uid is found
     */
    public static PGPSecretKey extractSecretSigningKeyFromKeyrings(final PGPSecretKeyRingCollection pgpSec, final String signingKeyUid)
            throws PGPException {

        PGPSecretKey key = null;

        final Iterator<PGPSecretKeyRing> rIt = pgpSec.getKeyRings(signingKeyUid, true);
        while (key == null && rIt.hasNext()) {
            final PGPSecretKeyRing kRing =  rIt.next();
            final Iterator<PGPSecretKey> kIt = kRing.getSecretKeys();

            while (key == null && kIt.hasNext()) {
                final PGPSecretKey k =  kIt.next();

                if (k.isSigningKey()) {
                    key = k;
                }
            }
        }

        if (key == null) {
            throw new PGPException("Can't find signing key in key ring.");
        }
        LOGGER.debug("Extracted secret signing key for UID '{}'.", signingKeyUid);

        return key;
    }

    /**
     * Returns the first encryption key encountered in {@code publicKeyRing}.
     *
     * @param publicKeyRing the public key ring
     * @return the encryption key
     */
    static PGPPublicKey getEncryptionKey(final PGPPublicKeyRing publicKeyRing) {
        PGPPublicKey returnKey = null;
        final Iterator<?> kIt = publicKeyRing.getPublicKeys();
        while (returnKey == null && kIt.hasNext()) {
            final PGPPublicKey k = (PGPPublicKey) kIt.next();
            if (k.isEncryptionKey()) {
                returnKey = k;
            }
        }
        return returnKey;
    }

    /**
     * Extracts the public key with UID {@code publicKeyUid} from key ring collection {@code publicKeyRings}.
     *
     * @param publicKeyUid   the public key uid
     * @param publicKeyRings the public key rings
     * @return the pGP public key ring
     * @throws PGPException the pGP exception
     */
    static PGPPublicKeyRing extractPublicKey(final String publicKeyUid,
                                              final PGPPublicKeyRingCollection publicKeyRings)
            throws PGPException {
        // the true parameter indicates, that partial matching of the publicKeyUid is enough.
        final Iterator<?> keyRings = publicKeyRings.getKeyRings(publicKeyUid, true);
        PGPPublicKeyRing returnKeyRing = null;
        while (keyRings.hasNext()) {
            final Object currentKeyRing = keyRings.next();
            if (currentKeyRing instanceof PGPPublicKeyRing) {
                if (returnKeyRing == null) {
                    returnKeyRing = (PGPPublicKeyRing) currentKeyRing;
                } else {
                    throw new PGPException("Multiple public key rings found for UID '" + publicKeyUid + "'!");
                }
            }
        }
        if (returnKeyRing == null) {
            throw new PGPException("No public key ring found for UID '" + publicKeyUid + "'!");
        }
        LOGGER.debug("Extracted public key ring for UID '{}' with first key strength {}.", publicKeyUid, returnKeyRing
                .getPublicKey().getBitStrength());
        return returnKeyRing;
    }
}
