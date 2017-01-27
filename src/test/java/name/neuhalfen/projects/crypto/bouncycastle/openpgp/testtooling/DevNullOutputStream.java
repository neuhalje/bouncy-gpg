package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Eats all data written into it.
 */
public class DevNullOutputStream extends OutputStream {

    private int bytesWritten = 0;

    @Override
    public void write(int i) throws IOException {
        // ignore
        bytesWritten++;
    }

    @Override
    public void write(byte[] b) throws IOException {
        // ignore
        bytesWritten += b.length;
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        // ignore
        bytesWritten += len;
    }

    public int getBytesWritten() {
        return bytesWritten;
    }
}
