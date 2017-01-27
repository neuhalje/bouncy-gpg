package name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting;


import org.bouncycastle.openpgp.*;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.SignatureException;

class Helpers {
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(Helpers.class);

    /**
     * Copy signed decrypted bytes.
     *
     * @param out     the out  -- Data is written here. Stream is not closed afterwards.
     * @param message the message
     * @param ops     the ops
     * @throws IOException        Signals that an I/O exception has occurred.
     * @throws SignatureException the signature exception
     */
    static void copySignedDecryptedBytes(final OutputStream out, PGPLiteralData message, final PGPOnePassSignature ops)
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
        // Do NOT close the bOut output stream bc. it would close out
        // and must not be closed according to the contract.
        bOut.flush();
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
    static boolean verifySignature(final PGPObjectFactory pgpFact, final PGPOnePassSignature ops) throws IOException,
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


}
