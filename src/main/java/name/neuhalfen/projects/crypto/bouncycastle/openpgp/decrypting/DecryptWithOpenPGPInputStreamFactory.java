package name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting;


import name.neuhalfen.projects.crypto.bouncycastle.openpgp.shared.PGPUtilities;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchProviderException;
import java.util.Iterator;

public class DecryptWithOpenPGPInputStreamFactory {
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(DecryptWithOpenPGPInputStreamFactory.class);


    private final PGPContentVerifierBuilderProvider pgpContentVerifierBuilderProvider = new BcPGPContentVerifierBuilderProvider();
    private final DecryptionConfig config;

    public static DecryptWithOpenPGPInputStreamFactory create(final DecryptionConfig config, SignatureValidationStrategy signatureValidationStrategy) {
        return new DecryptWithOpenPGPInputStreamFactory(config, signatureValidationStrategy);
    }

    private final SignatureValidationStrategy signatureValidationStrategy;

    public DecryptWithOpenPGPInputStreamFactory(final DecryptionConfig config, SignatureValidationStrategy signatureValidationStrategy) {
        this.signatureValidationStrategy = signatureValidationStrategy;
        this.config = config;
    }

    public InputStream wrapWithDecryptAndVerify(InputStream in) throws IOException {
        LOGGER.trace("Trying to decrypt and verify PGP Encryption.");
        try {
            final PGPObjectFactory factory = new PGPObjectFactory(PGPUtil.getDecoderStream(in), config.getKeyFingerPrintCalculator());

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
                    sKey = PGPUtilities.findSecretKey(config.getSecretKeyRings(), pbe.getKeyID(), config.decryptionSecretKeyPassphraseForSecretKeyId(pbe.getKeyID()));
                }
                if (sKey == null) {
                    // Wrong passphrases already trigger a throw in PGPUtilities.findSecretKey.
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
                PGPObjectFactory nextFactory = new PGPObjectFactory(((PGPCompressedData) pgpObj).getDataStream(), config.getKeyFingerPrintCalculator());
                return nextDecryptedStream(nextFactory, state);
            } else if (pgpObj instanceof PGPOnePassSignatureList) {
                LOGGER.trace("Found instance of PGPOnePassSignatureList");

                if (!signatureValidationStrategy.isRequireSignatureCheck()) {
                    LOGGER.info("Signature check disabled - ignoring contained signature");
                } else {
                    state.factory = factory;

                    // verify the signature
                    final PGPOnePassSignatureList onePassSignatures = (PGPOnePassSignatureList) pgpObj;
                    for (PGPOnePassSignature signature : onePassSignatures) {
                        final PGPPublicKey pubKey = config.getPublicKeyRings().getPublicKey(signature.getKeyID());
                        if (pubKey != null) {
                            LOGGER.trace("public key found for ID '{}'", signature.getKeyID());
                            signature.init(pgpContentVerifierBuilderProvider, pubKey);
                            state.addSignature(signature);
                        } else {
                            LOGGER.trace("No public key found for ID '{}'", signature.getKeyID());
                        }
                    }

                    if (state.numSignatures() == 0) {
                        throw new PGPException("None of the public keys used in signatures found for signature checking'!");
                    }
                }

            } else if (pgpObj instanceof PGPLiteralData) {
                LOGGER.trace("Found instance of PGPLiteralData");

                if (signatureValidationStrategy.isRequireSignatureCheck()) {
                    if (state.numSignatures() == 0) {
                        throw new PGPException("Message was not signed!");
                    } else {
                        return new SignatureValidatingInputStream(((PGPLiteralData) pgpObj).getInputStream(), state, signatureValidationStrategy);
                    }
                } else {
                    return ((PGPLiteralData) pgpObj).getInputStream();
                }
            } else {// keep on searching...
                LOGGER.debug("Skipping pgp Object of Type {}", pgpObj.getClass().getSimpleName());
            }

        }
        throw new PGPException("No data found");

    }

}