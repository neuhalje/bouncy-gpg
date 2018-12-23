package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.matcher;

import java.util.Iterator;
import java.util.regex.Pattern;
import javax.annotation.RegEx;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.hamcrest.Description;
import org.hamcrest.TypeSafeMatcher;

public class SecretKeyringWithUserIdMatcher extends TypeSafeMatcher<PGPSecretKeyRing> {

  private final Pattern userId;

  private SecretKeyringWithUserIdMatcher(final Pattern userId) {
    this.userId = userId;
  }

  static SecretKeyringWithUserIdMatcher uid(final String uid) {
    return new SecretKeyringWithUserIdMatcher(Pattern.compile(".*" + Pattern.quote(uid) + ".*"));
  }

  static SecretKeyringWithUserIdMatcher regexp(@RegEx final String uidRegexp) {
    return new SecretKeyringWithUserIdMatcher(Pattern.compile(uidRegexp));
  }

  @Override
  protected boolean matchesSafely(final PGPSecretKeyRing item) {
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
}

