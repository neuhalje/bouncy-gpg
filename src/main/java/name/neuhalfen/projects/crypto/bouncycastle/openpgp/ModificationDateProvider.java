package name.neuhalfen.projects.crypto.bouncycastle.openpgp;

import java.io.OutputStream;
import java.util.Date;

/**
 * Modification date provider.
 *
 * @see org.bouncycastle.openpgp.PGPLiteralDataGenerator#open(OutputStream, char, String, Date, byte[])
 */
public interface ModificationDateProvider {

    /**
     * Default instance which provides modification date as a current date.
     */
    ModificationDateProvider DEFAULT_INSTANCE = Date::new;

    /**
     * Provide desired modification date.
     *
     * @return modification date (<b>never {@code null}</b>)
     */
    Date getModificationDate();
}
