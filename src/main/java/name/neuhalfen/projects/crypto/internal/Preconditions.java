package name.neuhalfen.projects.crypto.internal;

import javax.annotation.Nullable;

/**
 * Idea borrowed from google guava.
 */
public final class Preconditions {

  /*
   * Prevent instantiation
   */
  private Preconditions() {
  }


  /**
   * <p>Throw a IllegalArgumentException when 'expression' is false.
   * </p><p>
   * Call this function in methods to check parameters.
   * </p>
   *
   * @param expression expression that must be true, else the exception is raised
   * @param message message passed to the exception
   *
   * @throws IllegalArgumentException expression is false
   */
  public static void checkArgument(boolean expression, @Nullable String message) {
    if (!expression) {
      throw new IllegalArgumentException(nonNullString(message));
    }
  }

  /**
   * <p>Throw a IllegalArgumentException when 'expression' is false.
   * </p><p>
   * Call this function in methods to check parameters.
   * </p>
   *
   * @param expression expression that must be true, else the exception is raised
   *
   * @throws IllegalArgumentException expression is false
   */
  public static void checkArgument(boolean expression) {
    if (!expression) {
      throw new IllegalArgumentException();
    }
  }


  /**
   * <p>Throw a IllegalStateException when 'expression' is false.
   * </p><p>
   * Call this function in methods to check state.
   * </p>
   *
   * @param expression expression that must be true, else the exception is raised
   * @param message message passed to the exception
   *
   * @throws IllegalStateException expression is false
   */
  public static void checkState(boolean expression, @Nullable String message) {
    if (!expression) {
      throw new IllegalStateException(nonNullString(message));
    }
  }

  /**
   * <p>Throw a IllegalStateException when 'expression' is false.
   * </p><p>
   * Call this function in methods to check state.
   * </p>
   *
   * @param expression expression that must be true, else the exception is raised
   *
   * @throws IllegalStateException expression is false
   */
  public static void checkState(boolean expression) {
    if (!expression) {
      throw new IllegalStateException();
    }
  }

  private static String nonNullString(String string) {
    return (string == null) ? "" : string;
  }

}
