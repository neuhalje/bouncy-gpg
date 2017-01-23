package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting;


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

}
