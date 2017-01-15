package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * A file based ZipEntityStrategy that puts the contents of the exploded ZIP
 * under a given root directory.
 *
 * All file names are appended with ".gpg"
 */
public class FSZipEntityStrategy implements ZipEntityStrategy {
    private final File destRootDir;

    public FSZipEntityStrategy(File destRootDir) {
        this.destRootDir = destRootDir;
    }

    @Override
    public void handleDirectory(String sanitizedDirectoryName) throws IOException {
        File destPath = new File(destRootDir, sanitizedDirectoryName);
        boolean success = destPath.mkdir();
        if (!success) throw new IOException("Failed to create '" + destPath + "'");
    }

    @Override
    public OutputStream createOutputStream(String sanitizedFileName) throws IOException {
        final String fileName = sanitizedFileName + ".gpg";

        File destPath = new File(destRootDir, fileName);
        FileOutputStream fos = new
                FileOutputStream(destPath);
        return fos;
    }
}
