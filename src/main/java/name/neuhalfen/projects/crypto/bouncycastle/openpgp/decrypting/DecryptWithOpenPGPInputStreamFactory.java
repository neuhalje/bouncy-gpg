package name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.shared.PGPUtilities;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Iterator;

public class DecryptWithOpenPGPInputStreamFactory {


    // make sure the Bouncy Castle provider is available:
    // because of this we can avoid declaring throws NoSuchProviderException further down
    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(DecryptWithOpenPGPInputStreamFactory.class);

    /**
     * List of all public key rings to be used.
     */
    private final PGPPublicKeyRingCollection publicKeyRings;

    /**
     * List of all secret key rings to be used.
     */
    private final PGPSecretKeyRingCollection secretKeyRings;

    /**
     * The decryption secret key passphrase.
     */
    private final char[] decryptionSecretKeyPassphrase;

    /**
     * Enforce signature - fail when no valid signature is found.
     */
    private final boolean decryptionSignatureCheckRequired;


    private final KeyFingerPrintCalculator keyFingerPrintCalculator = new BcKeyFingerprintCalculator();
    private final PGPContentVerifierBuilderProvider pgpContentVerifierBuilderProvider = new BcPGPContentVerifierBuilderProvider();

    public static DecryptWithOpenPGPInputStreamFactory create(final DecryptionConfig config) throws IOException {
        return new DecryptWithOpenPGPInputStreamFactory(config);
    }

    public DecryptWithOpenPGPInputStreamFactory(final DecryptionConfig config) throws IOException {
        try {
            this.publicKeyRings =
                    new PGPPublicKeyRingCollection(
                            PGPUtil.getDecoderStream(
                                    config.getPublicKeyRing()), keyFingerPrintCalculator);

            this.secretKeyRings =
                    new PGPSecretKeyRingCollection(
                            PGPUtil.getDecoderStream(config.getSecretKeyRing()), keyFingerPrintCalculator);

            this.decryptionSecretKeyPassphrase = config.getDecryptionSecretKeyPassphrase().toCharArray();

            this.decryptionSignatureCheckRequired = config.isSignatureCheckRequired();
        } catch (PGPException e) {
            throw new IOException("Failed to create DecryptWithOpenPGP", e);
        }
    }

    public InputStream wrapWithDecryptAndVerify(InputStream in) throws IOException {
        LOGGER.trace("Trying to decrypt and verify PGP Encryption.");
        try {
            final PGPObjectFactory factory = new PGPObjectFactory(PGPUtil.getDecoderStream(in), keyFingerPrintCalculator);

            return nextDecryptedStream(factory, new SignatureValidatingInputStream.DecryptionState());

        } catch (NoSuchProviderException anEx) {
            // This can't happen because we made sure of it in the static part at the top
            throw new AssertionError("Bouncy Castle Provider is needed");
        } catch (PGPException e) {
            throw new IOException("Failure decrypting", e);
        }
    }



    /**
     * Handles PGP objects in decryption process by recursively calling itself.
     *
     * @param factory PGPObjectFactory to access the next objects, might be recreated within this method
     * @param state   Decryption state, e.g. used for signature validation
     * @throws PGPException            the pGP exception
     * @throws IOException             Signals that an I/O exception has occurred.
     * @throws NoSuchProviderException should never occur, see static code part
     * @throws SignatureException      the signature exception
     */
    private InputStream nextDecryptedStream(PGPObjectFactory factory, SignatureValidatingInputStream.DecryptionState state) throws PGPException, IOException, NoSuchProviderException {

        Object pgpObj;

        while ((pgpObj = factory.nextObject()) != null) {

            if (pgpObj instanceof PGPEncryptedDataList) {
                LOGGER.trace("Found instance of PGPEncryptedDataList");
                PGPEncryptedDataList enc = (PGPEncryptedDataList) pgpObj;
                final Iterator<?> it = enc.getEncryptedDataObjects();

                if (!it.hasNext()) {
                    throw new PGPException("Decryption failed - No encrypted data found!");
                }
                //
                // find the secret key
                //
                PGPPrivateKey sKey = null;
                PGPPublicKeyEncryptedData pbe = null;
                while (sKey == null && it.hasNext()) {
                    pbe = (PGPPublicKeyEncryptedData) it.next();
                    sKey = PGPUtilities.findSecretKey(this.secretKeyRings, pbe.getKeyID(), this.decryptionSecretKeyPassphrase);
                }
                if (sKey == null) {
                    throw new PGPException(
                            "Decryption failed - No secret key was found in the key ring matching the public key used "
                                    + "to encrypt the file, aborting");
                }
                // decrypt the data

                final InputStream plainText = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));
                PGPObjectFactory nextFactory = new PGPObjectFactory(plainText, new BcKeyFingerprintCalculator());
                return nextDecryptedStream(nextFactory, state);
            } else if (pgpObj instanceof PGPCompressedData) {
                LOGGER.trace("Found instance of PGPCompressedData");
                PGPObjectFactory nextFactory = new PGPObjectFactory(((PGPCompressedData) pgpObj).getDataStream(), new BcKeyFingerprintCalculator());
                return nextDecryptedStream(nextFactory, state);
            } else if (pgpObj instanceof PGPOnePassSignatureList) {
                LOGGER.trace("Found instance of PGPOnePassSignatureList");

                if (!decryptionSignatureCheckRequired) {
                    LOGGER.info("Signature check disabled - ignoring contained signature");
                } else {
                    // verify the signature
                    state.ops = ((PGPOnePassSignatureList) pgpObj).get(0);
                    state.factory = factory;
                    final PGPPublicKey pubKey = this.publicKeyRings.getPublicKey(state.ops.getKeyID());

                    if (pubKey == null) {
                        throw new PGPException("No public key found for ID '" + state.ops.getKeyID() + "'!");
                    }
                    state.ops.init(pgpContentVerifierBuilderProvider, pubKey);
                }

            } else if (pgpObj instanceof PGPLiteralData) {
                LOGGER.trace("Found instance of PGPLiteralData");

                if (decryptionSignatureCheckRequired) {
                    if (state.ops == null) {
                        throw new PGPException("Message was not signed!");
                    } else {
                        return new SignatureValidatingInputStream(((PGPLiteralData) pgpObj).getInputStream(), state);
                    }
                } else {
                    return ((PGPLiteralData) pgpObj).getInputStream();
                }
            } else {// keep on searching...
                LOGGER.debug("Skipping pgp Object of Type {}", pgpObj.getClass().getSimpleName());
            }

        }
        return null;

    }

}