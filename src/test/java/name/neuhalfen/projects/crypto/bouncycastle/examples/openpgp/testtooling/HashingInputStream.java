package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.testtooling;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Hash everything read  from this stream. Used in tests to verify large
 * datasets can be decrypted reliably.
 */
public class HashingInputStream extends FilterInputStream {
    private final MessageDigest digest;

    private byte[] calculatedDigest = {};

    public static HashingInputStream sha256(InputStream src) throws NoSuchAlgorithmException {
        return new HashingInputStream(MessageDigest.getInstance("SHA-256"), src);
    }

    public static HashingInputStream sha1(InputStream src) throws NoSuchAlgorithmException {
        return new HashingInputStream(MessageDigest.getInstance("SHA-1"), src);
    }

    private HashingInputStream(MessageDigest digest, InputStream src) {
        super(src);
        this.digest = digest;
    }

    @Override
    public int read() throws IOException {
        int i = super.read();
        if (i >= 0) {
            digest.update((byte) (i & 0xff));
        }
        return i;
    }

    @Override
    public int read(byte[] b) throws IOException {
        int i = super.read(b);
        if (i >= 0) {
            digest.update(b, 0, i);
        }
        return i;
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        int i = super.read(b, off, len);
        if (i >= 0) {
            digest.update(b, off, i);
        }
        return i;
    }

    @Override
    public long skip(long n) throws IOException {
        throw new RuntimeException("skip not supported");
    }

    @Override
    public int available() throws IOException {
        return super.available();
    }

    @Override
    public synchronized void mark(int readlimit) {
        throw new RuntimeException("reset not supported");
    }

    @Override
    public synchronized void reset() throws IOException {
        throw new IOException("reset not supported");
    }

    @Override
    public boolean markSupported() {
        return false;
    }

    @Override
    public void close() throws IOException {
        super.close();

        if (calculatedDigest.length == 0) {
            calculatedDigest = this.digest.digest();
        }
    }

    public String toString() {
        return javax.xml.bind.DatatypeConverter.printHexBinary(calculatedDigest);
    }
}
