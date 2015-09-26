package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.decrypting;


import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.shared.PGPUtilities;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPGPContentVerifierBuilderProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.SignatureException;
import java.util.Iterator;

public class DecryptWithOpenPGP implements StreamDecryption {


    // make sure the Bouncy Castle provider is available:
    // because of this we can avoid declaring throws NoSuchProviderException further down
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * The Constant LOGGER.
     */
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(DecryptWithOpenPGP.class);


    /**
     * Milliseconds per second.
     */
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
     * The signature required.
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
            throw new RuntimeException(e);
        }
    }

    @Override
    public void decryptAndVerify(final InputStream is, final OutputStream os) throws IOException,
            SignatureException {
        final long starttime = System.currentTimeMillis();
        LOGGER.info("Trying to decrypt and verify PGP Encryption.");
        try {
            final PGPObjectFactory factory = new PGPObjectFactory(PGPUtil.getDecoderStream(is), keyFingerPrintCalculator);

            handlePgpObject(factory, this.decryptionSecretKeyPassphrase, null, os);

        } catch (NoSuchProviderException anEx) {
            // This can't happen because we made sure of it in the static part at the top
            LOGGER.error("Bouncy Castle not available!?", anEx);
            throw new AssertionError("Bouncy Castle Provider is needed");
        } catch (PGPException e) {
            throw new RuntimeException(e);
        } finally {
            os.close();
        }
        LOGGER.debug("Decrypt and verify duration {}s", (System.currentTimeMillis() - starttime) / MLLIES_PER_SEC);

    }

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
    private PGPPrivateKey findSecretKey(final PGPSecretKeyRingCollection pgpSec, final long keyID, final char[] pass)
            throws PGPException, NoSuchProviderException {
        LOGGER.debug("Finding secret key for decryption with key ID '{}'", Long.valueOf(keyID).toString());
        final PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);

        if (pgpSecKey == null) {
            return null;
        }
        return PGPUtilities.extractPrivateKey(pgpSecKey, pass);
    }

    /**
     * Handles PGP objects in decryption process by recursively calling itself.
     *
     * @param factory             PGPObjectFactory to access the next objects, might be recreated within this method
     * @param secretKeyPassphrase to access the secret key for decryption
     * @param ops                 Signature object, may be null
     * @param out                 the stream to write decrypted data to
     * @throws PGPException            the pGP exception
     * @throws IOException             Signals that an I/O exception has occurred.
     * @throws NoSuchProviderException should never occur, see static code part
     * @throws SignatureException      the signature exception
     */
    protected void handlePgpObject(PGPObjectFactory factory, final char[] secretKeyPassphrase, PGPOnePassSignature ops,
                                   final OutputStream out) throws PGPException, IOException, NoSuchProviderException, SignatureException {

        final Object pgpObj = factory.nextObject();
        if (pgpObj == null) {
            throw new PGPException("Decryption failed - No encrypted data found!");
        } else if (pgpObj instanceof PGPEncryptedDataList) {
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
                sKey = this.findSecretKey(this.secretKeyRings, pbe.getKeyID(), secretKeyPassphrase);
            }
            if (sKey == null) {
                throw new PGPException(
                        "Decryption failed - No secret key was found in the key ring matching the public key used "
                                + "to encrypt the file, aborting");
            }
            // decrypt the data

            final InputStream plainText = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));
            final PGPObjectFactory newFactory = new PGPObjectFactory(plainText, new BcKeyFingerprintCalculator());
            LOGGER.info("File decrypted successfully, now checking Signature");
            handlePgpObject(newFactory, secretKeyPassphrase, ops, out);

        } else if (pgpObj instanceof PGPCompressedData) {
            LOGGER.debug("Found instance of PGPCompressedData");
            final PGPCompressedData cData = (PGPCompressedData) pgpObj;
            factory = new PGPObjectFactory(cData.getDataStream(), new BcKeyFingerprintCalculator());
            handlePgpObject(factory, secretKeyPassphrase, ops, out);

        } else if (pgpObj instanceof PGPOnePassSignatureList) {
            LOGGER.debug("Found instance of PGPOnePassSignatureList");

            if (!decryptionSignatureCheckRequired) {
                LOGGER.info("Signature check disabled - ignoring contained signature");
                handlePgpObject(factory, secretKeyPassphrase, ops, out);
                return;
            }

            // verify the signature
            final PGPOnePassSignature newOps = ((PGPOnePassSignatureList) pgpObj).get(0);
            final PGPPublicKey pubKey = this.publicKeyRings.getPublicKey(newOps.getKeyID());

            if (pubKey == null) {
                throw new PGPException("No public key found for ID '" + newOps.getKeyID() + "'!");
            }
            newOps.init(pgpContentVerifierBuilderProvider, pubKey);
            handlePgpObject(factory, secretKeyPassphrase, newOps, out);

            final boolean successfullyVerified = verifySignature(factory, newOps);
            if (successfullyVerified) {
                LOGGER.debug(" *** Signature verification success *** ");
            } else {
                throw new SignatureException("Signature verification failed!");
            }

        } else if (pgpObj instanceof PGPLiteralData) {
            LOGGER.debug("Found instance of PGPLiteralData");
            if (decryptionSignatureCheckRequired && ops == null) {
                throw new PGPException("Message was not signed!");
            }
            copySignedDecryptedBytes(out, (PGPLiteralData) pgpObj, ops);

        } else {// keep on searching...
            LOGGER.debug("Skipping pgp Object of Type {}", pgpObj.getClass().getSimpleName());
            handlePgpObject(factory, secretKeyPassphrase, ops, out);
        }

    }

    /**
     * Verify signature.
     *
     * @param pgpFact the pgp fact
     * @param ops     the ops
     * @return true, if successful
     * @throws IOException        Signals that an I/O exception has occurred.
     * @throws PGPException       the pGP exception
     * @throws SignatureException the signature exception
     */
    private boolean verifySignature(final PGPObjectFactory pgpFact, final PGPOnePassSignature ops) throws IOException,
            PGPException, SignatureException {
        // verify the signature
        final PGPSignatureList signatureList = (PGPSignatureList) pgpFact.nextObject();

        if (signatureList == null || signatureList.isEmpty()) {
            throw new PGPException("No signatures found!");
        }

        final PGPSignature messageSignature = signatureList.get(0);

        if (messageSignature == null) {
            throw new PGPException("No message signature found!");
        }
        return ops.verify(messageSignature);
    }

    /**
     * Copy signed decrypted bytes.
     *
     * @param out     the out
     * @param message the message
     * @param ops     the ops
     * @throws IOException        Signals that an I/O exception has occurred.
     * @throws SignatureException the signature exception
     */
    private static void copySignedDecryptedBytes(final OutputStream out, PGPLiteralData message, final PGPOnePassSignature ops)
            throws IOException, SignatureException {

        final BufferedOutputStream bOut = new BufferedOutputStream(out);

        // use of buffering to speed up write
        final byte[] buffer = new byte[1 << 16];
        final InputStream fIn = message.getInputStream();

        // central copy operation
        int bytesRead;
        while ((bytesRead = fIn.read(buffer)) != -1) {
            bOut.write(buffer, 0, bytesRead);
            if (ops != null) {
                ops.update(buffer, 0, bytesRead);
            }
        }
        bOut.close();
    }
}