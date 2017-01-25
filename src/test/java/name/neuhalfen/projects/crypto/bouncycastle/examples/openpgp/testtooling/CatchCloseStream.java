package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.testtooling;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * relict from tracking down "Close" related issues. This is only used to set a breakpoint on 'close'
 */
public final class CatchCloseStream extends FilterInputStream {
    private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory.getLogger(CatchCloseStream.class);

    public static InputStream wrap(String name, InputStream is) {
        return new CatchCloseStream(name, is);
    }

    private final String name;

    private CatchCloseStream(final String name, InputStream in) {
        super(in);
        this.name = name;
    }

    @Override
    public void close() throws IOException {
        LOGGER.debug("Closing " + name);
        super.close();
    }
}
