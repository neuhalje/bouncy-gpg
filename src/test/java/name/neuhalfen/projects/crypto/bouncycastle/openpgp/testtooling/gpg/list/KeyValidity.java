package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling.gpg.list;

/**
 * - o :: Unknown (this key is new to the system)
 * - i :: The key is invalid (e.g. due to a missing self-signature)
 * - d :: The key has been disabled (deprecated - use the 'D' in field 12 instead)
 * - r :: The key has been revoked
 * - e :: The key has expired
 * - - :: Unknown validity (i.e. no value assigned)
 * - q :: Undefined validity.  '-' and 'q' may safely be treated as the same value for most
 * purposes
 * - n :: The key is not valid
 * - m :: The key is marginal valid.
 * - f :: The key is fully valid
 * - u :: The key is ultimately valid.  This often means that the secret key is available, but
 * any
 * key may be marked as ultimately valid.
 * - w :: The key has a well known private part.
 * - s :: The key has special validity.  This means that it might be self-signed and expected to
 * be used in the STEED system.
 */
public enum KeyValidity {
  UNKNWON_NEW('o'),
  INVALID('i'),
  DISABLED('d'),
  REVOKED('r'),
  EXPIRED('e'),
  UNKNOWN_NO_VALUE('-'),
  UNDEFINED('q'),
  NOT_VALID('n'),
  MARGINAL('m'),
  FULLY('f'),
  ULTIMATE('u'),
  WELL_KNOWN('w'),
  SPECIAL('s'),
  UNDEFINED_BY_STANDARD('X');

  private final char c;

  KeyValidity(final char c) {
    this.c = c;
  }

  public static KeyValidity forField(char fieldValue) {
    for (final KeyValidity v : values()) {
      if (v.c == fieldValue) {
        return v;
      }
    }
    return UNDEFINED_BY_STANDARD;
  }

  public static KeyValidity forField(String fieldValue) {
    if (fieldValue.length() == 1) {
      return KeyValidity.forField(fieldValue.charAt(0));
    } else {
      return  KeyValidity.UNDEFINED_BY_STANDARD;
    }
  }
}
