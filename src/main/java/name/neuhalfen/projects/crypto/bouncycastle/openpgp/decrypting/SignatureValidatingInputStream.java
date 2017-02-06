package name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignatureValidationStrategy;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignature;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.SignatureException;
import java.util.HashMap;
import java.util.Map;


final class SignatureValidatingInputStream extends FilterInputStream {

    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(SignatureValidatingInputStream.class);

    final static class DecryptionState {
        PGPObjectFactory factory;
        private Map<Long, PGPOnePassSignature> onePassSignatures = new HashMap<>();

        void updateOnePassSignatures(byte data) {
            for (PGPOnePassSignature sig : onePassSignatures.values()) {
                sig.update(data);
            }
        }

        void updateOnePassSignatures(byte[] b, int off, int len) {
            for (PGPOnePassSignature sig : onePassSignatures.values()) {
                sig.update(b, off, len);
            }
        }

        Map<Long, PGPOnePassSignature> getOnePassSignatures() {
            return onePassSignatures;
        }

        void addSignature(PGPOnePassSignature signature) {
            onePassSignatures.put(signature.getKeyID(), signature);
        }

        int numSignatures() {
            return onePassSignatures.size();
        }
    }

    private final DecryptionState state;
    private final SignatureValidationStrategy signatureValidationStrategy;

    /**
     * Creates a <code>SignatureValidatingInputStream</code>
     * by assigning the  argument <code>in</code>
     * to the field <code>this.in</code> so as
     * to remember it for later use.
     *
     * @param in the underlying input stream, or <code>null</code> if
     *           this instance is to be created without an underlying stream.
     */
    SignatureValidatingInputStream(InputStream in, DecryptionState state, SignatureValidationStrategy signatureValidationStrategy) {
        super(in);
        this.state = state;
        this.signatureValidationStrategy = signatureValidationStrategy;
    }

    @Override
    public int read() throws IOException {
        final int data = super.read();
        if (data != -1) {
            state.updateOnePassSignatures((byte) data);
        } else {
            validateSignature();
        }
        return data;
    }

    @Override
    public int read(byte[] b) throws IOException {
        int read = super.read(b);
        if (read != -1) {
            state.updateOnePassSignatures(b, 0, read);
        } else {
            validateSignature();
        }
        return read;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int read = super.read(b, off, len);
        if (read != -1) {
            state.updateOnePassSignatures(b, off, read);
        } else {
            validateSignature();
        }
        return read;
    }

    /**
     * Ensure that at least ONE signature is valid.
     *
     * @throws IOException No valid signature found
     */
    private void validateSignature() throws IOException {
        try {
            signatureValidationStrategy.validateSignatures(state.factory, state.getOnePassSignatures());
        } catch (PGPException | SignatureException e) {
            throw new IOException(e.getMessage(), e);
        }

    }

    @Override
    public long skip(long n) throws IOException {
        throw new UnsupportedOperationException("Skipping not supported");
    }

    @Override
    public synchronized void mark(int readlimit) {
        throw new UnsupportedOperationException("mark not supported");
    }

    @Override
    public synchronized void reset() throws IOException {
        throw new UnsupportedOperationException("reset not supported");
    }

    @Override
    public boolean markSupported() {
        return false;
    }
}
