package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher;

import java.util.Iterator;
import org.bouncycastle.bcpg.SymmetricKeyAlgorithmTags;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;

/**
 * Check that _all_ secret keys are encrypted.
 */
public class SecretKeyringEncryptedMatcher extends TypeSafeMatcher<PGPSecretKeyRing> {


  private SecretKeyringEncryptedMatcher() {
  }

  /**
   * Check that _all_ secret keys are encrypted.
   */
  static Matcher<PGPSecretKeyRing> secretKeyIsEncrypted() {
    return new SecretKeyringEncryptedMatcher();
  }

  @Override
  protected boolean matchesSafely(final PGPSecretKeyRing item) {
    try {

      boolean allKeysEncrypted = true;

      final Iterator<PGPSecretKey> secretKeys = item.getSecretKeys();

      while (secretKeys.hasNext()) {
        final PGPSecretKey key = secretKeys.next();

        // Keys without private keys do not need to be encrypted
        if (!key.isPrivateKeyEmpty()) {
          final boolean isEncrypted =
              key.getKeyEncryptionAlgorithm() != SymmetricKeyAlgorithmTags.NULL;
          allKeysEncrypted &= isEncrypted;
        }
      }
      return allKeysEncrypted;
    } catch (Exception e) {
      return false;
    }
  }

  @Override
  protected void describeMismatchSafely(final PGPSecretKeyRing item,
      final Description mismatchDescription) {
    mismatchDescription.appendText("is encrypted");
  }

  @Override
  public void describeTo(final Description description) {
    description.appendText("is encrypted");
  }
}

