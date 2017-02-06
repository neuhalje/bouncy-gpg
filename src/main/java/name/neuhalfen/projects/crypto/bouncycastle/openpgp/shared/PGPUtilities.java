package name.neuhalfen.projects.crypto.bouncycastle.openpgp.shared;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.security.NoSuchProviderException;
import java.util.Iterator;


/**
 * FIXME: Cleanup code, throw out duplicates etc
 */
public class PGPUtilities {
    // Use the EncryptWithOpenPGP logger to maintain log format against original version
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(PGPUtilities.class);

    /**
     * Find secret key.
     *
     * @param pgpSec the pgp sec
     * @param keyID  the key id
     * @param pass   the pass
     * @return the pGP private key
     * @throws PGPException            the pGP exception
     * @throws NoSuchProviderException the no such provider exception
     * @return the decrypted secret key
     */
    public static PGPPrivateKey findSecretKey(final PGPSecretKeyRingCollection pgpSec, final long keyID, final char[] pass)
            throws PGPException, NoSuchProviderException {
        LOGGER.trace("Finding secret key for decryption with key ID '0x{}'", Long.toHexString(keyID));
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
     * @return The decrypted key
     * @throws PGPException E.g. wrong passphrase
     * @return the decrypted secret key
     */
    public static PGPPrivateKey extractPrivateKey(PGPSecretKey encryptedKey, final char[] passphrase) throws PGPException {
        LOGGER.trace("Extracting secret key for decryption with key ID '0x{}'", Long.toHexString(encryptedKey.getKeyID()));

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

    /**
     * Extract a signing key from the keyring. There must be only one signing key.
     * .
     * FIXME: refactor this, so that we use all key from the keyring as valid signing keys
     * .
     * Detection of possible signing keys is heuristic at best.
     *
     * @throws PGPException Multiple signing (encryption) keys found in keyring
     * @param keyring search here
     * @return a public key that can be used for signing
     */
    public static PGPPublicKey extractSigningPublicKey(PGPPublicKeyRing keyring) throws PGPException {

        PGPPublicKey ret = null;
        for (PGPPublicKey pubKey : keyring) {
            if (pubKey.isEncryptionKey() && !pubKey.isMasterKey()) {
                if (ret != null) {
                    throw new PGPException(String.format("Multiple signing (encryption) keys found in keyring (e.g. 0x%x and 0x%x)", pubKey.getKeyID(), ret.getKeyID()));
                } else {
                    ret = pubKey;
                }
            }
        }
        return ret;
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

        PGPSecretKey key = null;

        final Iterator<PGPSecretKeyRing> rIt = pgpSec.getKeyRings(signingKeyUid, true);
        while (key == null && rIt.hasNext()) {
            final PGPSecretKeyRing kRing = rIt.next();
            final Iterator<PGPSecretKey> kIt = kRing.getSecretKeys();

            while (key == null && kIt.hasNext()) {
                final PGPSecretKey k = kIt.next();

                if (k.isSigningKey()) {
                    key = k;
                }
            }
        }

        if (key == null) {
            throw new PGPException("Can't find signing key in key ring.");
        }
        LOGGER.trace("Extracted secret signing key for UID '{}'.", signingKeyUid);

        return key;
    }

    /**
     * Returns the first encryption key encountered in {@code publicKeyRing}.
     *
     * @param publicKeyRing the public key ring
     * @return the encryption key
     * @deprecated Use explicit uid for signing
     */
    public static PGPPublicKey getEncryptionKey(final PGPPublicKeyRing publicKeyRing) {
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
