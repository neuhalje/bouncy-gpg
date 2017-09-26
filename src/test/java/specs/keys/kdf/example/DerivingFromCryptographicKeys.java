package specs.keys.kdf.example;

import static specs.helper.InputConverters.ByteArray.toHexString;

import org.concordion.api.extension.Extensions;
import org.concordion.ext.apidoc.ExecutableSpecExtension;
import org.concordion.integration.junit4.ConcordionRunner;
import org.junit.runner.RunWith;

@RunWith(ConcordionRunner.class)
@Extensions(ExecutableSpecExtension.class)
public class DerivingFromCryptographicKeys {


  public String toHex(byte[] bytes) {
    return toHexString(bytes);
  }

  public static class KeyAndMetaData {

    public final String derivedKey;

    public final int derivedKeyLen;

    public KeyAndMetaData(String derivedKey, int derivedKeyLen) {
      this.derivedKey = derivedKey;
      this.derivedKeyLen = derivedKeyLen;
    }

    public static KeyAndMetaData fromKeyMaterial(byte[] key) {
      return new KeyAndMetaData(toHexString(key), key.length * 8);
    }
  }

}
