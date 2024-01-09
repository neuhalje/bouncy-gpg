package name.neuhalfen.projects.crypto.bouncycastle.openpgp;

import java.io.OutputStream;
import java.util.Date;

/**
 * Name provider.
 *
 * @see org.bouncycastle.openpgp.PGPLiteralDataGenerator#open(OutputStream, char, String, Date, byte[])
 */
public interface NameProvider {

    /**
     * Default instance which provides an empty string ({@code ""}) as a name.
     */
    NameProvider DEFAULT_INSTANCE = () -> "";

    /**
     * Provide desired name.
     *
     * @return name (never <b>never {@code null}</b>)
     */
    String getName();
}


