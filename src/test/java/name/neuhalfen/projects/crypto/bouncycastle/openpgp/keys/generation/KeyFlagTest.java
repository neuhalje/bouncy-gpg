package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.empty;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

import org.junit.Test;

public class KeyFlagTest {

  @Test
  public void fromInteger_withZero_yieldsEmptySet() {
    assertThat(KeyFlag.fromInteger(0), empty());
  }

  @Test
  public void fromInteger_withSingleFlag_yieldsCorrectSet() {
    assertThat(KeyFlag.fromInteger(KeyFlag.CERTIFY_OTHER.getFlag()),
        containsInAnyOrder(KeyFlag.CERTIFY_OTHER));
  }


  @Test
  public void fromInteger_withTwoFlags_yieldsCorrectSet() {
    assertThat(
        KeyFlag.fromInteger(
            KeyFlag.CERTIFY_OTHER.getFlag() | KeyFlag.ENCRYPT_COMMS.getFlag()),
        containsInAnyOrder(KeyFlag.CERTIFY_OTHER, KeyFlag.ENCRYPT_COMMS));
  }


  @Test(expected = IllegalArgumentException.class)
  public void fromInteger_withUnknownFlag_throws() {
    KeyFlag.fromInteger(1 << 16);
  }

  @Test
  public void fromInteger_withUnknownFlag_throwsWithCorrectMessage() {
    try {
      KeyFlag.fromInteger(1 << 16);
    } catch (IllegalArgumentException e) {
      assertEquals(e.getMessage(),
          "Could not identify the following KeyFlags: 0b10000000000000000");
    }
  }
}