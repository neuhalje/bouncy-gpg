package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.util.Iterator;


/**
 * FIXME: Cleanup code, throw out duplicates etc
 */
public final class PGPUtilities {
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(PGPUtilities.class);

    /**
     * Find secret key.
     *
     * @param pgpSec the pgp sec
     * @param keyID  the key id
     * @param pass   the pass
     * @return the decrypted secret key
     * @throws PGPException            the pGP exception
     */
    public static PGPPrivateKey findSecretKey(final PGPSecretKeyRingCollection pgpSec, final long keyID, final char[] pass)
            throws PGPException {
        LOGGER.debug("Finding secret key with key ID '0x{}'", Long.toHexString(keyID));
        final PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }
        return PGPUtilities.extractPrivateKey(pgpSecKey, pass);
    }

    /**
     * Decrypt an encrypted PGP secret key.
     *
     * @param encryptedKey An encrypted key
     * @param passphrase   The passphrase for the key
     * @return the decrypted secret key
     * @throws PGPException E.g. wrong passphrase
     */
    public static PGPPrivateKey extractPrivateKey(PGPSecretKey encryptedKey, final char[] passphrase) throws PGPException {
        LOGGER.debug("Extracting secret key with key ID '0x{}'", Long.toHexString(encryptedKey.getKeyID()));

        PGPDigestCalculatorProvider calcProvider = new JcaPGPDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build();

        PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder(
                calcProvider).setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(passphrase);

        return encryptedKey.extractPrivateKey(decryptor);
    }

    /**
     * Extracts the public key with UID {@code publicKeyUid} from key ring collection {@code publicKeyRings}.
     *
     * @param publicKeyUid   the public key uid, e.g. sender@example.com
     * @param publicKeyRings the public key rings
     * @return the PGP public key ring containing the userId
     * @throws PGPException E.g. multiple keyrings for same uid OR key not found in keyrings
     */
    public static PGPPublicKeyRing extractPublicKeyRingForUserId(final String publicKeyUid,
                                                                 final PGPPublicKeyRingCollection publicKeyRings)
            throws PGPException {
        if (publicKeyUid == null) {
            throw new NullPointerException("publicKeyUid must not be null");
        }
        if (publicKeyRings == null) {
            throw new NullPointerException("publicKeyRings must not be null");
        }

        // the true parameter indicates, that partial matching of the publicKeyUid is enough.
        final Iterator<?> keyRings = publicKeyRings.getKeyRings("<" + publicKeyUid + ">", true);
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
        LOGGER.debug("Extracted public key ring for UID '{}' with key strength {}.", publicKeyUid, returnKeyRing
                .getPublicKey().getBitStrength());
        return returnKeyRing;
    }

    /**
     * Extract a signing key from the keyring. The implementation tries to find the
     * best matching key.
     * .
     * FIXME: refactor this, so that we use all key from the keyring as valid signing keys
     * .
     * Detection of possible signing keys is heuristic at best.
     *
     * @param keyring search here
     * @return a public key that can be used for signing
     */
    public static PGPPublicKey extractSigningPublicKey(PGPPublicKeyRing keyring) {

        int highestScore = Integer.MIN_VALUE;

        PGPPublicKey ret = null;

        for (PGPPublicKey pubKey : keyring) {
            int score = calculateSigningKeyScore(pubKey);
            if (score > highestScore) {
                ret = pubKey;
                highestScore = score;
            }
        }
        return ret;
    }

    /*
     * Try to find the best signing key.
     * - Try not to use master keys (if possible) because signing should be done with subkeys
     * - Give a bonus to "sign only" keys (or 'AUTH' only keys - these are not detected)
     */
    private static int calculateSigningKeyScore(PGPPublicKey pubKey) {
        int score = 0;
        if (!pubKey.isMasterKey()) {
            score += 100;
        }
        if (!pubKey.isEncryptionKey()) {
            score += 10;
        }
        return score;
    }


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
        int highestScore = Integer.MIN_VALUE;

        PGPSecretKey key = null;

        final Iterator<PGPSecretKeyRing> ringIterator = pgpSec.getKeyRings("<" + signingKeyUid + ">", true);
        while (ringIterator.hasNext()) {
            final PGPSecretKeyRing kRing = ringIterator.next();
            final Iterator<PGPSecretKey> secretKeyIterator = kRing.getSecretKeys();

            while (secretKeyIterator.hasNext()) {
                final PGPSecretKey k = secretKeyIterator.next();
                int score = calculateSigningKeyScore(k.getPublicKey());

                if (k.isSigningKey() && (score > highestScore)) {
                    key = k;
                    highestScore = score;
                }
            }
        }

        if (key == null) {
            throw new PGPException(String.format("Can't find signing key for uid '%s' in key ring.", signingKeyUid));
        }
        LOGGER.trace("Extracted secret signing key for UID '{}'.", signingKeyUid);

        return key;
    }

    /**
     * Returns the 'best' encryption key encountered in {@code publicKeyRing}.
     *
     * @param publicKeyRing the public key ring
     * @return the encryption key
     */
    public static PGPPublicKey getEncryptionKey(final PGPPublicKeyRing publicKeyRing) {
        int score;
        int highestScore = Integer.MIN_VALUE;

        PGPPublicKey returnKey = null;

        for (PGPPublicKey pubKey : publicKeyRing) {
            score = calculateEncryptionKeyScore(pubKey);
            if (score > highestScore) {
                returnKey = pubKey;
                highestScore = score;
            }
        }
        return returnKey;
    }

    /*
    * Try to find the best encryption key.
    * - Try not to use master keys (if possible) because encryption should be done with subkeys
    */
    private static int calculateEncryptionKeyScore(PGPPublicKey pubKey) {
        if (!pubKey.isEncryptionKey()) return Integer.MIN_VALUE;

        int score = 0;
        if (!pubKey.isMasterKey()) {
            score++;
        }

        return score;
    }
}
