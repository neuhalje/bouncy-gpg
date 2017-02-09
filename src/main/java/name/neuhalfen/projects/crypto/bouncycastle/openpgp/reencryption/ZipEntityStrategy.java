package name.neuhalfen.projects.crypto.bouncycastle.openpgp.reencryption;

import javax.annotation.Nullable;
import java.io.IOException;
import java.io.OutputStream;

/**
 * Strategy for handling the content of an encrypted ZIP file.
 * <p>
 * The data flow is:
 * <p>
 * [encrypted data from e.g test.zip.gpg]
 * * for each file/dir
 * -- [name sanitation]
 * -- ZipEntityStrategy::handleDirectory -- e.g. create directory
 * OR
 * -- output := ZipEntityStrategy::createOutputStream -- e.g. create a FileOutputStream
 * -- writeEncryptedFileContent(output)
 */
public interface ZipEntityStrategy {


    /**
     * Sanitize the names of entities in ZIP files. These can contain absolute paths, and path traversals.
     *
     * @param nameFromZip name of the file/directory as seen in the ZIP
     * @return rewritten name
     */
    String rewriteName(String nameFromZip);

    /**
     * Handle a directory. The names are guaranteed to have be sanitized by  {@link #rewriteName(String)}
     *
     * @param sanitizedDirectoryName Name of the directory as returned by {@link #rewriteName(String)}
     * @throws IOException Well, can happen
     */
    void handleDirectory(String sanitizedDirectoryName) throws IOException;

    /**
     * Create an outputstream that will receive the (re-)encrypted  content of one file in the ZIP
     *
     * @param sanitizedFileName Name of the file as returned by {@link #rewriteName(String)}
     * @return data sink. Null: Ignore the file
     * @throws IOException Well, can happen
     */
    @Nullable
    OutputStream createOutputStream(String sanitizedFileName) throws IOException;
}
