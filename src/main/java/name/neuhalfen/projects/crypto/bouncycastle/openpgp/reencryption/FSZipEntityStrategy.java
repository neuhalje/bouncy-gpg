package name.neuhalfen.projects.crypto.bouncycastle.openpgp.reencryption;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.regex.Pattern;
import javax.annotation.Nullable;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.internal.Preconditions;

/**
 * A file based ZipEntityStrategy that puts the contents of the exploded ZIP under a given root
 * directory. . All file names are appended with ".gpg"
 */
public class FSZipEntityStrategy implements ZipEntityStrategy {

  private static final Pattern REMOVE_LEADING_RELATIVE_PATH = Pattern
      .compile("^(([.]{2,})|/|\\\\)*", Pattern.COMMENTS);

  private static final Pattern REMOVE_DOT_DOT_REGEXP = Pattern.compile("[.]{2,}", Pattern.COMMENTS);
  private static final Pattern REMOVE_FOLLOWING_REGEXP = Pattern
      .compile("[^a-zA-Z0-9_, +-./\\\\]", Pattern.COMMENTS);

  private final File destRootDir;

  public FSZipEntityStrategy(File destRootDir) {
    this.destRootDir = destRootDir;
  }

  @Override
  public void handleDirectory(String sanitizedDirectoryName) throws IOException {
    Preconditions.checkNotNull(sanitizedDirectoryName, "sanitizedDirectoryName must not be null");

    File destPath = new File(destRootDir, sanitizedDirectoryName);
    boolean success = destPath.mkdir();
    if (!success) {
      throw new IOException("Failed to create '" + destPath + "'");
    }
  }

  @Override
  public
  @Nullable
  OutputStream createOutputStream(String sanitizedFileName) throws IOException {
    Preconditions.checkNotNull(sanitizedFileName, "sanitizedFileName must not be null");

    final String fileName = sanitizedFileName + ".gpg";

    File destPath = new File(destRootDir, fileName);
    FileOutputStream fos = new
        FileOutputStream(destPath);
    return fos;
  }

  @SuppressWarnings("PMD.LawOfDemeter")
  @Override
  public String rewriteName(String nameFromZip) {
    Preconditions.checkNotNull(nameFromZip, "nameFromZip must not be null");

    final String withOutLeadingRelativePath = REMOVE_LEADING_RELATIVE_PATH.matcher(nameFromZip)
        .replaceAll("");
    final String withoutDotDot = REMOVE_DOT_DOT_REGEXP.matcher(withOutLeadingRelativePath)
        .replaceAll("");
    final String sanitizedMiddlePart = REMOVE_FOLLOWING_REGEXP.matcher(withoutDotDot)
        .replaceAll("");
    return sanitizedMiddlePart;
  }
}
