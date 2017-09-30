package specs.helper;

import static specs.helper.InputConverters.ByteArray.toHexString;

public class KeyAndMetaData {

  public final String derivedKey;
  public final int derivedKeyLen;

  public KeyAndMetaData(String derivedKey, int derivedKeyLen) {
    this.derivedKey = derivedKey;
    this.derivedKeyLen = derivedKeyLen;
  }

  public static KeyAndMetaData fromKeyMaterial(byte[] key) {
    return new KeyAndMetaData(toHexString(key), key.length * 8);
  }

  public static KeyAndMetaData fromKeyMaterial(String hex) {
    //
    return fromKeyMaterial(InputConverters.ByteArray.fromHexString(hex));
  }
}
