package name.neuhalfen.projects.crypto.internal;

public final class DataFormatter {
  private final static char[] HEX_GLYPHS = "0123456789ABCDEF".toCharArray();

  private DataFormatter() {
  }


  public static String byteArrayToHexString(final byte[] bytes) {
    final char[] ret = new char[bytes.length * 2];
    for (int i = 0; i < bytes.length; i++) {
      int unsignedValue = bytes[i] & 0xFF;
      ret[i * 2] = HEX_GLYPHS[unsignedValue >>> 4];
      ret[i * 2 + 1] = HEX_GLYPHS[unsignedValue & 0x0F];
    }
    return new String(ret);
  }

}
