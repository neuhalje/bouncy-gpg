package name.neuhalfen.projects.crypto.bouncycastle.openpgp.internal;

import javax.annotation.Nullable;

/**
 * Idea borrowed from google guava
 */
public final class Preconditions {

  public static <T> T checkNotNull(T reference) {
    if (reference == null) {
      throw new NullPointerException();
    }
    return reference;
  }

  public static <T> T checkNotNull(T reference, @Nullable String message) {
    if (reference == null) {
      throw new NullPointerException(nonNullString(message));
    }
    return reference;
  }

  public static void checkArgument(boolean expression, @Nullable String message) {
    if (!expression) {
      throw new IllegalArgumentException(nonNullString(message));
    }
  }

  public static void checkArgument(boolean expression) {
    if (!expression) {
      throw new IllegalArgumentException();
    }
  }

  private static String nonNullString(String s) {
    if (s == null) {
      return "";
    } else {
      return s;
    }
  }

}
