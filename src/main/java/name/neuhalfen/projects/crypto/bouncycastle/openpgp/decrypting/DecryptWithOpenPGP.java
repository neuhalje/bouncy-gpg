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
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Iterator;

public class DecryptWithOpenPGP {


    // make sure the Bouncy Castle provider is available:
    // because of this we can avoid declaring throws NoSuchProviderException further down
    static {
        Security.addProvider(new BouncyCastleProvider());
    }


    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(DecryptWithOpenPGP.class);
    private static final int MLLIES_PER_SEC = 1000;

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

    public DecryptWithOpenPGP(final DecryptionConfig config) throws IOException {

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
            throw new RuntimeException("Failed to create DecryptWithOpenPGP", e);
        }
    }

    public void decryptAndVerify(final InputStream is, final OutputStream os) throws IOException,
            SignatureException {
        final long starttime = System.currentTimeMillis();
        LOGGER.info("Trying to decrypt and verify PGP Encryption.");
        try {
            final PGPObjectFactory factory = new PGPObjectFactory(PGPUtil.getDecoderStream(is), keyFingerPrintCalculator);

            handlePgpObject(factory, null, os);

        } catch (NoSuchProviderException anEx) {
            // This can't happen because we made sure of it in the static part at the top
            throw new AssertionError("Bouncy Castle Provider is needed");
        } catch (PGPException e) {
            throw new IOException("Failure decrypting", e);
        }
        LOGGER.debug("Decrypt and verify duration {}s", (System.currentTimeMillis() - starttime) / MLLIES_PER_SEC);
    }

    /**
     * Handles PGP objects in decryption process by recursively calling itself.
     *
     * @param factory PGPObjectFactory to access the next objects, might be recreated within this method
     * @param ops     Signature object, may be null
     * @param out     the stream to write decrypted data to. The stream is not closed.
     * @throws PGPException            the pGP exception
     * @throws IOException             Signals that an I/O exception has occurred.
     * @throws NoSuchProviderException should never occur, see static code part
     * @throws SignatureException      the signature exception
     */
    void handlePgpObject(PGPObjectFactory factory, PGPOnePassSignature ops,
                         final OutputStream out) throws PGPException, IOException, NoSuchProviderException, SignatureException {

        final Object pgpObj = factory.nextObject();
        if (pgpObj == null) {
            throw new PGPException("Decryption failed - No encrypted data found!");
        } else if (pgpObj instanceof PGPEncryptedDataList) {
            LOGGER.trace("Found instance of PGPEncryptedDataList");
            final PGPEncryptedDataList enc = (PGPEncryptedDataList) pgpObj;
            handleEncryptedDataObjects(enc, ops, out);

        } else if (pgpObj instanceof PGPCompressedData) {
            LOGGER.trace("Found instance of PGPCompressedData");
            handleCompressedData((PGPCompressedData) pgpObj, ops, out);

        } else if (pgpObj instanceof PGPOnePassSignatureList) {
            LOGGER.trace("Found instance of PGPOnePassSignatureList");
            handleOnePassSignatureList((PGPOnePassSignatureList) pgpObj, factory, ops, out);

        } else if (pgpObj instanceof PGPLiteralData) {
            LOGGER.trace("Found instance of PGPLiteralData");
            if (decryptionSignatureCheckRequired && ops == null) {
                throw new PGPException("Message was not signed!");
            }
            Helpers.copySignedDecryptedBytes(out, (PGPLiteralData) pgpObj, ops);

        } else {// keep on searching...
            LOGGER.info("Skipping unknown pgp Object of Type {}", pgpObj.getClass().getSimpleName());
            handlePgpObject(factory, ops, out);
        }

    }

    private void handleOnePassSignatureList(PGPOnePassSignatureList pgpObj, PGPObjectFactory factory, PGPOnePassSignature ops, OutputStream out) throws PGPException, IOException, NoSuchProviderException, SignatureException {
        if (!decryptionSignatureCheckRequired) {
            LOGGER.info("Signature check disabled - ignoring contained signature");
            handlePgpObject(factory, ops, out);
            return;
        }

        // verify the signature
        final PGPOnePassSignature newOps = pgpObj.get(0);
        final PGPPublicKey pubKey = this.publicKeyRings.getPublicKey(newOps.getKeyID());

        if (pubKey == null) {
            throw new PGPException("No public key found for ID '" + newOps.getKeyID() + "'!");
        }
        newOps.init(pgpContentVerifierBuilderProvider, pubKey);
        handlePgpObject(factory, newOps, out);

        final boolean successfullyVerified = Helpers.verifySignature(factory, newOps);
        if (successfullyVerified) {
            LOGGER.trace(" *** Signature verification success *** ");
        } else {
            throw new SignatureException("Signature verification failed!");
        }
    }

    private void handleCompressedData(PGPCompressedData pgpObj, PGPOnePassSignature ops, OutputStream out) throws PGPException, IOException, NoSuchProviderException, SignatureException {
        final PGPObjectFactory factory = new PGPObjectFactory(pgpObj.getDataStream(), new BcKeyFingerprintCalculator());
        handlePgpObject(factory, ops, out);
    }

    private void handleEncryptedDataObjects(PGPEncryptedDataList enc, PGPOnePassSignature ops, OutputStream out) throws PGPException, NoSuchProviderException, IOException, SignatureException {
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
        final PGPObjectFactory newFactory = new PGPObjectFactory(plainText, new BcKeyFingerprintCalculator());
        LOGGER.trace("File decrypted successfully, now checking Signature");
        handlePgpObject(newFactory, ops, out);
    }

}