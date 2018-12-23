package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher;

import java.util.Iterator;
import java.util.Set;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;

/**
 * Check that a keys has the correct length.
 */
@SuppressWarnings("PMD.LawOfDemeter")
public class KeyLengthMatcher extends TypeSafeMatcher<PGPSecretKey> {


  private final Set<Integer> allowedKeyLengths;

  private KeyLengthMatcher(
      final Set<Integer> allowedKeyLengths) {
    this.allowedKeyLengths = allowedKeyLengths;
  }

  private static String toString(Set<Integer> allowedKeyLengths) {
    final StringBuilder builder = new StringBuilder();
    if (allowedKeyLengths.isEmpty()) {
      builder.append("<none>");
    } else {
      final Iterator<Integer> i = allowedKeyLengths.iterator();
      builder.append(i.next());
      while (i.hasNext()) {
        builder.append(", ").append(i.next());
      }
    }
    return builder.toString();
  }

  static Matcher<PGPSecretKey> hasKeyLength(final Set<Integer> allowedKeyLengths) {
    return new KeyLengthMatcher(allowedKeyLengths);
  }

  @Override
  protected boolean matchesSafely(final PGPSecretKey item) {
    try {
      return allowedKeyLengths.contains(item.getPublicKey().getBitStrength());
    } catch (Exception e) {
      return false;
    }
  }

  @Override
  protected void describeMismatchSafely(final PGPSecretKey item,
      final Description mismatchDescription) {
    mismatchDescription.appendText(" should have a key length of ")
        .appendText(toString(allowedKeyLengths))
        .appendText(" but is ")
        .appendValue(item.getPublicKey().getBitStrength());
  }

  @Override
  public void describeTo(final Description description) {
    description.appendText("is encrypted");
  }
}

