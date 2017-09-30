package specs.keys.kdf.example;

import static specs.helper.InputConverters.ByteArray.fromHexString;
import static specs.helper.InputConverters.ByteArray.toHexString;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import name.neuhalfen.projects.crypto.symmetric.keygeneration.DerivedKeyGenerator;
import name.neuhalfen.projects.crypto.symmetric.keygeneration.DerivedKeyGeneratorFactory;
import org.concordion.api.extension.Extensions;
import org.concordion.ext.apidoc.ExecutableSpecExtension;
import org.concordion.integration.junit4.ConcordionRunner;
import org.junit.runner.RunWith;
import specs.helper.KeyAndMetaData;

@RunWith(ConcordionRunner.class)
@Extensions(ExecutableSpecExtension.class)
public class DerivingFromCryptographicKeys {

  public static final String MASTER_KEY = "0x81d0994d0aa21b786d6b8dc45fc09f31";
  public static final String SALT = "0xb201445d3bcdc7a07c469b7d7ef8988c";

  public String toHex(byte[] bytes) {
    return toHexString(bytes);
  }

  public KeyAndMetaData deriveKey(String context, String idUniqueInContext, String recordVersion) throws GeneralSecurityException {
    context = context.trim();
    idUniqueInContext=idUniqueInContext.trim();
    recordVersion=recordVersion.trim();

    byte[] masterkey = fromHexString(MASTER_KEY);
    byte[] salt = fromHexString(SALT);

    final DerivedKeyGenerator derivedKeyGenerator = DerivedKeyGeneratorFactory
        .fromInputKey(masterkey).andSalt(salt).withHKDFsha256();

    final byte iv[] = new byte[128 / 8];
    final byte key[] = new byte[128 / 8];
    {
      final byte[] keyAndIV = derivedKeyGenerator
          .deriveKey(context, idUniqueInContext, recordVersion,(iv.length + key.length)*8);
      System.arraycopy(keyAndIV, 0, key, 0, key.length);
      System.arraycopy(keyAndIV, key.length, iv, 0, iv.length);
    }

    return KeyAndMetaData.fromKeyMaterial(key);
  }

  public byte[] aesGCM(byte[] nonce, byte[] keyBytes)
      throws InvalidAlgorithmParameterException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException, IllegalBlockSizeException {
    GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH_BITS, nonce);

    final SecretKey secretKeySpec = new SecretKeySpec(keyBytes, "AES");

    final Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
    aes.init(Cipher.ENCRYPT_MODE, secretKeySpec, gcmParameterSpec);
    aes.updateAAD(AUTHENTICATED_NOT_ENCRYPTED.getBytes(StandardCharsets.UTF_8));
    aes.update(ENCRYPTED_AND_AUTHENTICATED.getBytes(StandardCharsets.UTF_8));
    final byte[] cipherText = aes.doFinal();
    return cipherText;
  }


  private static final int GCM_TAG_LENGTH_BITS = 96;
  public static final String ENCRYPTED_AND_AUTHENTICATED = "Authenticated and encrypted";
  public static final String AUTHENTICATED_NOT_ENCRYPTED = "Authenticated, not encrypted";

}
