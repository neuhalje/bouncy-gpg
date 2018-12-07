package specs.keys.passwords.example;

import static specs.helper.InputConverters.ByteArray.fromHexString;
import static specs.helper.InputConverters.ByteArray.toHexString;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.internal.Preconditions;
import name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.stretching.KeyStretching;
import name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.stretching.SCryptKeyStretching;
import org.concordion.api.extension.Extensions;
import org.concordion.ext.apidoc.ExecutableSpecExtension;
import org.concordion.integration.junit4.ConcordionRunner;
import org.junit.runner.RunWith;

@RunWith(ConcordionRunner.class)
@Extensions(ExecutableSpecExtension.class)
public class ConvertingPasswordsIntoCryptographicKeys {

  public KeyAndMetaData stretchWithFixedParameters(String password)
      throws GeneralSecurityException {
    return stretchWithFixedParameters(password, 128);
  }

  public KeyAndMetaData stretchWithFixedParameters(String password, int desiredLenInBits)
      throws GeneralSecurityException {

    Preconditions.checkNotNull(password, "password must not be null");

    password = password.trim();

    final KeyStretching streching = new SCryptKeyStretching(
        SCryptKeyStretching.SCryptKeyStretchingParameters.forModeratelyStongInputKeyMaterial());

    final byte[] SALT = fromHexString("0x01");
    final byte[] key = streching
        .strengthenKey(SALT, password.getBytes(StandardCharsets.UTF_8), desiredLenInBits);

    return KeyAndMetaData.fromKeyMaterial(key);
  }


  @SuppressWarnings("PMD.AvoidReassigningParameters")
  public KeyAndMetaData stretchWithSalt(String password, String saltAsHexString)
      throws GeneralSecurityException {

    Preconditions.checkNotNull(password, "password must not be null");
    Preconditions.checkNotNull(saltAsHexString, "saltAsHexString must not be null");

    password = password.trim();
    saltAsHexString = saltAsHexString.trim();

    final KeyStretching streching = new SCryptKeyStretching(
        SCryptKeyStretching.SCryptKeyStretchingParameters.forModeratelyStongInputKeyMaterial());

    final byte[] SALT = fromHexString(saltAsHexString);
    final byte[] key = streching
        .strengthenKey(SALT, password.getBytes(StandardCharsets.UTF_8), 128);

    return KeyAndMetaData.fromKeyMaterial(key);
  }

  public boolean isSaltChangesKey(String password) throws GeneralSecurityException {
    Preconditions.checkNotNull(password, "password must not be null");

    final KeyStretching streching = new SCryptKeyStretching(
        SCryptKeyStretching.SCryptKeyStretchingParameters.forModeratelyStongInputKeyMaterial());

    final byte[] SALT_1 = {0x1};

    final byte[] key_1 = streching
        .strengthenKey(SALT_1, password.getBytes(StandardCharsets.UTF_8), 128);
    final byte[] SALT_2 = {0x2};
    final byte[] key_2 = streching
        .strengthenKey(SALT_2, password.getBytes(StandardCharsets.UTF_8), 128);

    return !Arrays.equals(key_1, key_2);
  }

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
