package name.neuhalfen.projects.crypto.internal;

import static java.util.Objects.requireNonNull;

public final class DataFormatterHelper {

  private final static char[] HEX_GLYPHS = "0123456789ABCDEF".toCharArray();

  private DataFormatterHelper() {
  }


  public static String byteArrayToHexString(final byte[] bytes) {
    requireNonNull(bytes);
    final char[] ret = new char[bytes.length * 2];
    for (int i = 0; i < bytes.length; i++) {
      final int unsignedValue = bytes[i] & 0xFF;
      ret[i * 2] = HEX_GLYPHS[unsignedValue >>> 4];
      ret[i * 2 + 1] = HEX_GLYPHS[unsignedValue & 0x0F];
    }
    return new String(ret);
  }

}
