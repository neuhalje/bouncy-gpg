package name.neuhalfen.projects.crypto.internal;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

public class SetUtils {

  private SetUtils() {/* util class */}

  public static <T> Set<T> unmodifiableSet(T... elements) {
    final HashSet<T> set = new HashSet<T>(elements.length);

    Collections.addAll(set, elements);
    return Collections.unmodifiableSet(set);
  }

}
