package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher;

import java.util.Iterator;
import java.util.Set;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation.internal.KeyRingSubKeyFixUtil;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;

/**
 * This method tests sure if sub keys do consist of sub key packets.
 *
 * Bouncycastle versions up to and including 1.60 created {@link PGPSecretKeyRing}s which sub keys
 * consisted of
 * normal public key packets, which would result in lost keys when converting PGPSecretKeyRings to
 * PGPPublicKeyRings.
 *
 * @see <a href="https://github.com/bcgit/bc-java/issues/381">Bouncycastle Java bug report #381</a>
 */
public class SecretKeyringHasCorrectSubkeyPacketsMatcher extends TypeSafeMatcher<PGPSecretKeyRing> {


  private SecretKeyringHasCorrectSubkeyPacketsMatcher() {
  }

  /**
   * Check that _all_ secret keys are encrypted.
   */
  static Matcher<PGPSecretKeyRing> secretKeyIsEncrypted() {
    return new SecretKeyringHasCorrectSubkeyPacketsMatcher();
  }

  private static String violations(PGPSecretKeyRing item) {
    try {
      final Set<PGPSecretKey> violatingSubkeyPackets = KeyRingSubKeyFixUtil
          .violatingSubkeyPackets(item);
      if (violatingSubkeyPackets.isEmpty()) {
        return "<no violations>";
      }
      final StringBuilder b = new StringBuilder();
      final Iterator<PGPSecretKey> iterator = violatingSubkeyPackets.iterator();

      b.append(formatKeyId(iterator.next()));
      while (iterator.hasNext()) {
        b.append(", ").append(formatKeyId(iterator.next()));
      }
      return b.toString();
    } catch (Exception e) {
      return "Error while checking: " + e.toString();
    }
  }

  private static String formatKeyId(final PGPSecretKey key) {
    return "0x" + Long.toHexString(key.getKeyID());
  }

  static Matcher<PGPSecretKeyRing> secretKeyringHasCorrectSubkeyPackets() {
    return new SecretKeyringHasCorrectSubkeyPacketsMatcher();
  }

  @Override
  protected boolean matchesSafely(final PGPSecretKeyRing item) {
    try {

      return KeyRingSubKeyFixUtil.violatingSubkeyPackets(item).isEmpty();
    } catch (Exception e) {
      return false;
    }
  }

  @Override
  protected void describeMismatchSafely(final PGPSecretKeyRing item,
      final Description mismatchDescription) {
    mismatchDescription.appendText(
        "has it not set for the following IDs: ");
    mismatchDescription.appendText(violations(item));
  }

  @Override
  public void describeTo(final Description description) {
    description.appendText("should carry the PUBLIC_SUBKEY packet tag for all its subkeys");
  }
}

