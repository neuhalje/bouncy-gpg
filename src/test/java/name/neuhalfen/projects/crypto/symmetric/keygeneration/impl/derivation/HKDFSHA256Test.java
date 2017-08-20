package name.neuhalfen.projects.crypto.symmetric.keygeneration.impl.derivation;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.IsEqual.equalTo;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertNotNull;

import org.junit.Test;

public class HKDFSHA256Test {

  private final static byte[] SALT_1 = new byte[]{0x12, 0x34, 0x5};
  private final static byte[] SALT_2 = new byte[]{0x10, 0x09, 0x08};

  private final static byte[] KEY_1 = new byte[]{0x72, 0x74, 0x75};
  private final static byte[] KEY_2 = new byte[]{0x70, 0x79, 0x78};

  private final static byte[] INFO_1 = new byte[]{0x22, 0x24, 0x25};
  private final static byte[] INFO_2 = new byte[]{0x30, 0x39, 0x38};


  @Test
  public void deriveKey_isDeterministic() throws Exception {

    final HKDFSHA256 sut1 = new HKDFSHA256(KEY_1);
    final byte[] derivedKey1 = sut1.deriveKey(SALT_1, INFO_1, 128);

    final HKDFSHA256 sut2 = new HKDFSHA256(KEY_1);
    final byte[] derivedKey2_fromSameParameters = sut2.deriveKey(SALT_1, INFO_1, 128);

    assertNotNull(derivedKey1);
    assertNotNull(derivedKey2_fromSameParameters);
    assertThat(derivedKey1, equalTo(derivedKey2_fromSameParameters));

  }

  @Test
  public void deriveKey_instanceCanBeReused() throws Exception {
    final HKDFSHA256 sut = new HKDFSHA256(KEY_1);

    final byte[] derivedKey1 = sut.deriveKey(SALT_1, INFO_1, 128);
    final byte[] derivedKey2_fromSameParameters = sut.deriveKey(SALT_1, INFO_1, 128);

    assertNotNull(derivedKey1);
    assertNotNull(derivedKey2_fromSameParameters);
    assertThat(derivedKey1, equalTo(derivedKey2_fromSameParameters));
  }


  @Test
  public void deriveKey_honorsDesiredKeyLength() throws Exception {

    final HKDFSHA256 sut = new HKDFSHA256(KEY_1);

    final byte[] derivedKey = sut.deriveKey(SALT_1, INFO_1, 128);
    assertThat(derivedKey.length, equalTo(128 / 8));

  }

  @Test
  public void deriveKey_honorsDesiredKeyLength_Multi() throws Exception {

    final HKDFSHA256 sut = new HKDFSHA256(KEY_1);

    for (int bits = 8; bits <= 256; bits += 8) {
      final byte[] derivedKey = sut.deriveKey(SALT_1, INFO_1, bits);
      assertThat(derivedKey.length * 8, equalTo(bits));
    }
  }

  @Test
  public void deriveKey_differentInfo_returnsDifferentKey() throws Exception {
    final HKDFSHA256 sut = new HKDFSHA256(KEY_1);

    final byte[] derivedKey1 = sut.deriveKey(SALT_1, INFO_1, 128);
    final byte[] derivedKey2 = sut.deriveKey(SALT_1, INFO_2, 128);

    assertThat(derivedKey1, not(equalTo(derivedKey2)));
  }


  @Test
  public void deriveKey_differentSalt_returnsDifferentKey() throws Exception {
    final HKDFSHA256 sut = new HKDFSHA256(KEY_1);

    final byte[] derivedKey1 = sut.deriveKey(SALT_1, INFO_1, 128);
    final byte[] derivedKey2 = sut.deriveKey(SALT_2, INFO_1, 128);

    assertThat(derivedKey1, not(equalTo(derivedKey2)));
  }


  @Test
  public void deriveKey_differentIKM_returnsDifferentKey() throws Exception {
    final HKDFSHA256 sut1 = new HKDFSHA256(KEY_1);
    final byte[] derivedKey1 = sut1.deriveKey(SALT_1, INFO_1, 128);

    final HKDFSHA256 sut2 = new HKDFSHA256(KEY_2);
    final byte[] derivedKey2 = sut2.deriveKey(SALT_1, INFO_1, 128);

    assertThat(derivedKey1, not(equalTo(derivedKey2)));

  }
}