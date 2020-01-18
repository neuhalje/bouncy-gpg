package name.neuhalfen.projects.crypto.bouncycastle.openpgp.reencryption;

import static java.util.Objects.requireNonNull;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.StandardOpenOption;
import java.util.regex.Pattern;
import javax.annotation.Nullable;

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

  FSZipEntityStrategy(File destRootDir) {
    this.destRootDir = destRootDir;
  }

  @Override
  public void handleDirectory(String sanitizedDirectoryName) throws IOException {
    requireNonNull(sanitizedDirectoryName, "sanitizedDirectoryName must not be null");

    final File destPath = new File(destRootDir, sanitizedDirectoryName);
    final boolean success = destPath.mkdir();
    if (!success) {
      throw new IOException("Failed to create '" + destPath + "'");
    }
  }

  @Override
  public
  @Nullable
  OutputStream createOutputStream(String sanitizedFileName) throws IOException {
    requireNonNull(sanitizedFileName, "sanitizedFileName must not be null");

    final String fileName = sanitizedFileName + ".gpg";

    final File destPath = new File(destRootDir, fileName);
    return Files.newOutputStream(destPath.toPath(), StandardOpenOption.CREATE_NEW);
  }

  @SuppressWarnings({"PMD.LawOfDemeter","PMD.UnnecessaryLocalBeforeReturn"})
  @Override
  public String rewriteName(String nameFromZip) {
    requireNonNull(nameFromZip, "nameFromZip must not be null");

    final String withOutLeadingRelativePath = REMOVE_LEADING_RELATIVE_PATH.matcher(nameFromZip)
        .replaceAll("");
    final String withoutDotDot = REMOVE_DOT_DOT_REGEXP.matcher(withOutLeadingRelativePath)
        .replaceAll("");
    final String sanitizedMiddlePart = REMOVE_FOLLOWING_REGEXP.matcher(withoutDotDot)
        .replaceAll("");
    return sanitizedMiddlePart;
  }
}
