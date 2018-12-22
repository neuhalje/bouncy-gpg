package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher;

import java.util.Iterator;
import java.util.regex.Pattern;
import javax.annotation.RegEx;
import org.bouncycastle.openpgp.PGPPublicKeyRing;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;

public class PublicKeyringWithUserIdMatcher extends TypeSafeMatcher<PGPPublicKeyRing> {

  private final Pattern userId;

  private PublicKeyringWithUserIdMatcher(final Pattern userId) {
    this.userId = userId;
  }

  @Override
  protected boolean matchesSafely(final PGPPublicKeyRing item) {
    try {
      boolean matchesUserId = false;

      final Iterator<String> userIDs = item.getPublicKey().getUserIDs();
      while (userIDs.hasNext()) {
        final String uid = userIDs.next();
        matchesUserId |= userId.matcher(uid).matches();
      }
      return matchesUserId;
    } catch (Exception e) {
      return false;
    }
  }

  @Override
  public void describeTo(final Description description) {
    description.appendText("Matches regexp " + userId.toString());
  }

  static PublicKeyringWithUserIdMatcher uid(final String uid) {
    return new PublicKeyringWithUserIdMatcher(Pattern.compile(".*" + Pattern.quote(uid) + ".*"));
  }

  static PublicKeyringWithUserIdMatcher regexp(@RegEx final String uidRegexp) {
    return new PublicKeyringWithUserIdMatcher(Pattern.compile(uidRegexp));
  }
}

