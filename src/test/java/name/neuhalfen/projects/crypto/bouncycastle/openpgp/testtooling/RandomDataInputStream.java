package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling;


import java.io.IOException;
import java.io.InputStream;
import java.util.Random;

/**
 * Generate a defined amount of random input data.
 */
public class RandomDataInputStream extends InputStream {

    private final Random data;
    private long bytesLeft;

    //
    public RandomDataInputStream(final long size) {
        this.data = new Random();
        this.bytesLeft = size;
    }

    @Override
    public int read() throws IOException {

        if (bytesLeft > 0) {
            bytesLeft--;

            return data.nextInt(255);
        } else {
            return -1;
        }
    }

    @Override
    public int read(byte[] b) throws IOException {
        if (bytesLeft > 0) {
            int bytesRead = (int) Math.min(bytesLeft, b.length);
            bytesLeft -= bytesRead;
            data.nextBytes(b); // Ignore overwrite > bytesRead
            return bytesRead;
        } else {
            return -1;
        }
    }

    @Override
    public int read(byte[] b, int off, int len) throws IOException {
        if (off == 0 && len == b.length) {
            return read(b);
        } else {
            throw new UnsupportedOperationException(String.format("read(byte[%d],offset=%d,len=%d)", b.length, off, len));
        }

    }

    @Override
    public boolean markSupported() {
        return false;
    }

    @Override
    public int available() throws IOException {
        return (int) bytesLeft;
    }
}
