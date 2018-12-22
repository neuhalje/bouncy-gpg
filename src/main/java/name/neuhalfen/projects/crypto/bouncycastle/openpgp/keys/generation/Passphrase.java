/*
 * Copyright 2018 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.generation;

import java.util.Arrays;
import javax.annotation.Nullable;

public class Passphrase {

  private final Object lock = new Object();

  private final char[] chars;
  private boolean valid = true;

  /**
   * Passphrase for keys etc.
   *
   * @param chars may be null for empty passwords.
   */
  public Passphrase(@Nullable char[] chars) {
    this.chars = chars;
  }

  /**
   * Represents a {@link Passphrase} instance that represents no password.
   *
   * @return empty passphrase
   */
  public static Passphrase emptyPassphrase() {
    return new Passphrase(null);
  }

  /**
   * Overwrite the char array with spaces and mark the {@link Passphrase} as invalidated.
   */
  public void clear() {
    synchronized (lock) {
      if (chars != null) {
        Arrays.fill(chars, ' ');
      }
      valid = false;
    }
  }

  /**
   * Call {@link #clear()} to make sure the memory is overwritten.
   *
   * @throws Throwable bad things might happen in {@link Object#finalize()}.
   */
  @Override
  protected void finalize() throws Throwable {
    clear();
    super.finalize();
  }

  /**
   * Return a copy of the underlying char array.
   * A return value of {@code null} represents no password.
   *
   * @return passphrase chars.
   *
   * @throws IllegalStateException in case the password has been cleared at this point.
   */
  public @Nullable
  char[] getChars() {
    synchronized (lock) {
      if (!valid) {
        throw new IllegalStateException("Passphrase has been cleared.");
      }

      if (chars == null) {
        return null;
      }

      char[] copy = new char[chars.length];
      System.arraycopy(chars, 0, copy, 0, chars.length);
      return copy;
    }
  }

  /**
   * Return true if the passphrase has not yet been cleared.
   *
   * @return valid
   */
  public boolean isValid() {
    synchronized (lock) {
      return valid;
    }
  }
}
