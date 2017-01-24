package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.shared;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.PGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;

import java.security.NoSuchProviderException;
import java.util.Iterator;

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
     */
    public static PGPPrivateKey findSecretKey(final PGPSecretKeyRingCollection pgpSec, final long keyID, final char[] pass)
            throws PGPException, NoSuchProviderException {
        LOGGER.debug("Finding secret key for decryption with key ID '{}'", Long.valueOf(keyID).toString());
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
     * @param pass         The password for the key
     * @return The decrypted key
     * @throws PGPException
     */
    public static PGPPrivateKey extractPrivateKey(PGPSecretKey encryptedKey, final char[] pass) throws PGPException {
        PGPDigestCalculatorProvider calcProvider = new JcaPGPDigestCalculatorProviderBuilder()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME).build();
        PBESecretKeyDecryptor decryptor = new JcePBESecretKeyDecryptorBuilder(
                calcProvider).setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(pass);

        return encryptedKey.extractPrivateKey(decryptor);
    }

    /**
     * Extracts the public key with UID {@code publicKeyUid} from key ring collection {@code publicKeyRings}.
     *
     * @param publicKeyUid   the public key uid
     * @param publicKeyRings the public key rings
     * @return the pGP public key ring
     * @throws PGPException the pGP exception
     */
    public static PGPPublicKeyRing extractPublicKey(final String publicKeyUid,
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
