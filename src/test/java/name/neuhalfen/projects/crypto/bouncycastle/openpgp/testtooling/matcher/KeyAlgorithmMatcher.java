package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher;

import java.util.Iterator;
import java.util.Set;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.algorithms.PublicKeyAlgorithm;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.hamcrest.TypeSafeMatcher;

/**
 * Check that a keys has the correct algorithm.
 */
@SuppressWarnings("PMD.LawOfDemeter")
public class KeyAlgorithmMatcher extends TypeSafeMatcher<PGPSecretKey> {


  private final Set<PublicKeyAlgorithm> allowedAlgorithms;

  private KeyAlgorithmMatcher(
      final Set<PublicKeyAlgorithm> allowedAlgorithms) {
    this.allowedAlgorithms = allowedAlgorithms;
  }

  private static String toString(int algorithmId) {
    final StringBuilder builder = new StringBuilder();
    final PublicKeyAlgorithm algorithm = PublicKeyAlgorithm.fromId(algorithmId);
    if (algorithm == null) {
      builder.append("<unknown: 0x").append(Long.toHexString(algorithmId)).append(" >");
    } else {
      builder.append(algorithm);
    }
    return builder.toString();
  }

  private static String toString(Set<PublicKeyAlgorithm> algorithms) {
    final StringBuilder builder = new StringBuilder();
    if (algorithms.isEmpty()) {
      builder.append("<none>");
    } else {
      final Iterator<PublicKeyAlgorithm> i = algorithms.iterator();
      builder.append(i.next());
      while (i.hasNext()) {
        builder.append(", ").append(i.next());
      }
    }
    return builder.toString();
  }

  static Matcher<PGPSecretKey> keyAlgorithmAnyOf(final Set<PublicKeyAlgorithm> allowedAlgorithms) {
    return new KeyAlgorithmMatcher(allowedAlgorithms);
  }

  @Override
  protected boolean matchesSafely(final PGPSecretKey item) {
    try {

      final int algorithmId = item.getPublicKey().getAlgorithm();
      final PublicKeyAlgorithm algorithm = PublicKeyAlgorithm.fromId(algorithmId);

      return allowedAlgorithms.contains(algorithm);
    } catch (Exception e) {
      return false;
    }
  }

  @Override
  protected void describeMismatchSafely(final PGPSecretKey item,
      final Description mismatchDescription) {
    mismatchDescription.appendText(" should be one of ")
        .appendText(toString(allowedAlgorithms))
        .appendText(" but is ")
        .appendText(toString(item.getPublicKey().getAlgorithm()));
  }

  @Override
  public void describeTo(final Description description) {
    description.appendText("is encrypted");
  }
}

