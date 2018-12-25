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

import static java.util.Objects.requireNonNull;

import java.util.Arrays;
import javax.annotation.Nullable;

/**
 * Passphrase used during key generation.
 */
public class Passphrase {

  private final Object lock = new Object();

  @Nullable
  private final char[] chars;
  private final boolean empty;
  private boolean valid = true;

  /**
   * Passphrase for keys etc.
   *
   * @param chars may be null for empty passwords.
   */
  @SuppressWarnings("PMD.UseVarargs")
  public Passphrase(@Nullable char[] chars) {
    if (chars == null) {
      empty = true;
      this.chars = null; //NOPMD
    } else {
      this.chars = Arrays.copyOf(chars, chars.length);
      empty = chars.length <= 0;
    }
  }

  /**
   * Represents a {@link Passphrase} instance that represents no password.
   *
   * @return empty passphrase
   */
  public static Passphrase emptyPassphrase() {
    return new Passphrase(null);
  }

  public static Passphrase fromString(final String passphrase) {
    requireNonNull(passphrase);
    return new Passphrase(passphrase.toCharArray());
  }

  @SuppressWarnings("PMD.UseVarargs")
  public static Passphrase fromChars(final char[] passphrase) {
    requireNonNull(passphrase);
    return new Passphrase(passphrase);
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

      return chars == null ? null : Arrays.copyOf(chars, chars.length);
    }
  }

  /**
   * Return true if the passphrase is not empty.
   *
   * @return empty
   */
  public boolean isEmpty() {
    synchronized (lock) {
      return empty;
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
