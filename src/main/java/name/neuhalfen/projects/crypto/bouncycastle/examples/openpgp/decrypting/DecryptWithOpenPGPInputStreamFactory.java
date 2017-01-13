package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting;


import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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


    public DecryptWithOpenPGPInputStreamFactory(final DecryptionConfig config) throws IOException {
        try {
            // FIXME: Move this in some factory code

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

            LOGGER.error("Failed to create DecryptWithOpenPGP", e);
            throw new RuntimeException(e);
        }
    }

    public InputStream wrapWithDecryptAndVerify(InputStream in) throws IOException,
            SignatureException {
        LOGGER.debug("Trying to decrypt and verify PGP Encryption.");
        try {
            final PGPObjectFactory factory = new PGPObjectFactory(PGPUtil.getDecoderStream(in), keyFingerPrintCalculator);

            return nextDecryptedStream(factory, null);

        } catch (NoSuchProviderException anEx) {
            // This can't happen because we made sure of it in the static part at the top
            LOGGER.error("Bouncy Castle not available!?", anEx);
            throw new AssertionError("Bouncy Castle Provider is needed");
        } catch (PGPException e) {
            LOGGER.debug("Failure decrypting", e);
            throw new RuntimeException(e);
        } finally {
            in.close();
        }
    }

    /**
     * Handles PGP objects in decryption process by recursively calling itself.
     *
     * @param factory PGPObjectFactory to access the next objects, might be recreated within this method
     * @param ops     Signature object, may be null
     * @throws PGPException            the pGP exception
     * @throws IOException             Signals that an I/O exception has occurred.
     * @throws NoSuchProviderException should never occur, see static code part
     * @throws SignatureException      the signature exception
     */
    private InputStream nextDecryptedStream(PGPObjectFactory factory, PGPOnePassSignature ops) throws PGPException, IOException, NoSuchProviderException, SignatureException {

        Object pgpObj;

        while ((pgpObj = factory.nextObject()) != null) {

            if (pgpObj instanceof PGPEncryptedDataList) {
                LOGGER.debug("Found instance of PGPEncryptedDataList");
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
                    sKey = Helpers.findSecretKey(this.secretKeyRings, pbe.getKeyID(), this.decryptionSecretKeyPassphrase);
                }
                if (sKey == null) {
                    throw new PGPException(
                            "Decryption failed - No secret key was found in the key ring matching the public key used "
                                    + "to encrypt the file, aborting");
                }
                // decrypt the data

                final InputStream plainText = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));
                PGPObjectFactory nextFactory = new PGPObjectFactory(plainText, new BcKeyFingerprintCalculator());
                return nextDecryptedStream(nextFactory, ops);
            } else if (pgpObj instanceof PGPCompressedData) {
                LOGGER.debug("Found instance of PGPCompressedData");
                PGPObjectFactory nextFactory = new PGPObjectFactory(((PGPCompressedData) pgpObj).getDataStream(), new BcKeyFingerprintCalculator());
                return nextDecryptedStream(nextFactory, ops);
            } else if (pgpObj instanceof PGPOnePassSignatureList) {
                LOGGER.debug("Found instance of PGPOnePassSignatureList");

                if (!decryptionSignatureCheckRequired) {
                    LOGGER.info("Signature check disabled - ignoring contained signature");
                } else {
                    // verify the signature
                    ops = ((PGPOnePassSignatureList)pgpObj).get(0);
                    final PGPPublicKey pubKey = this.publicKeyRings.getPublicKey(ops.getKeyID());

                    if (pubKey == null) {
                        throw new PGPException("No public key found for ID '" + ops.getKeyID() + "'!");
                    }
                }

            } else if (pgpObj instanceof PGPLiteralData) {
                LOGGER.debug("Found instance of PGPLiteralData");
                if (decryptionSignatureCheckRequired && ops == null) {
                    throw new PGPException("Message was not signed!");
                }
                // FIXME: validation ; ops.update; ops.verify()


                return ((PGPLiteralData) pgpObj).getInputStream();

            } else {// keep on searching...
                LOGGER.debug("Skipping pgp Object of Type {}", pgpObj.getClass().getSimpleName());
            }

        }
        return null;

    }
}