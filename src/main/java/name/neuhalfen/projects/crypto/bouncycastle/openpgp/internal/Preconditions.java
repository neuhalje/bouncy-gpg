package name.neuhalfen.projects.crypto.bouncycastle.openpgp.internal;

import javax.annotation.Nullable;

/**
 * Idea borrowed from google guava.
 */
public final class Preconditions {

  /*
   * Prevent instantiation
   */
  private Preconditions(){}

  /**
   * Throw a NullPointerException when 'reference' is null.
   * <p/>
   * Call this function in methods to check parameters.
   * <p/>
   * checkNotNull returns the reference passed.
   *
   * @param reference value to be tested
   * @param <T>  type of the reference to be tested
   * @return the reference (for chaining)
   * @throws NullPointerException  reference is null
   */
  public static <T> T checkNotNull(T reference) {
    if (reference == null) {
      throw new NullPointerException();
    }
    return reference;
  }

  /**
   * Throw a NullPointerException when 'reference' is null.
   * <p/>
   * Call this function in methods to check parameters.
   * <p/>
   * checkNotNull returns the reference passed.
   *
   * @param reference value to be tested
   * @param message message passed to the exception
   * @param <T>  type of the reference to be tested
   * @return the reference (for chaining)
   * @throws NullPointerException  reference is null
   */
  public static <T> T checkNotNull(T reference, @Nullable String message) {
    if (reference == null) {
      throw new NullPointerException(nonNullString(message));
    }
    return reference;
  }


  /**
   * Throw a IllegalArgumentException when 'expression' is false.
   * <p/>
   * Call this function in methods to check parameters.
   *
   * @param expression expression that must be true, else the exception is raised
   * @param message message passed to the exception
   * @throws IllegalArgumentException  expression is false
   */
  public static void checkArgument(boolean expression, @Nullable String message) {
    if (!expression) {
      throw new IllegalArgumentException(nonNullString(message));
    }
  }

  /**
   * Throw a IllegalArgumentException when 'expression' is false.
   * <p/>
   * Call this function in methods to check parameters.
   *
   * @param expression expression that must be true, else the exception is raised
   * @throws IllegalArgumentException  expression is false
   */
  public static void checkArgument(boolean expression) {
    if (!expression) {
      throw new IllegalArgumentException();
    }
  }

  private static String nonNullString(String string) {
    return (string == null) ? "": string;
  }

}
