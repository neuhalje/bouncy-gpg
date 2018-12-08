package specs.helper;

import name.neuhalfen.projects.crypto.internal.Preconditions;
import org.bouncycastle.util.encoders.Hex;

public class InputConverters {

  public final static class ByteArray {

    public static String toHexString(byte[] bytes) {
      final StringBuilder sb = new StringBuilder("0x");
      for (byte b : bytes) {
        sb.append(String.format("%02x", b));
      }
      return sb.toString();
    }

    @SuppressWarnings("PMD.AvoidReassigningParameters")
    public static byte[] fromHexString(String hexString) {

      if (hexString.startsWith("0x")) {
        hexString = hexString.substring(2);
      }
      Preconditions.checkArgument(hexString.length() % 2 == 0,
          "String  length must be a multiple of 2");

      return Hex.decode(hexString);
    }
  }


}
