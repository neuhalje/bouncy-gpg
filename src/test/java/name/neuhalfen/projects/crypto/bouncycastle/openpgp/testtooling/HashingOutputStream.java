package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Hash everything written into this stream. Used in tests to verify large datasets can be decrypted
 * reliably. <p> The hash is made available via toString and calculated on close.
 */
public class HashingOutputStream extends OutputStream {

  private final MessageDigest digest;

  private byte[] calculatedDigest = {};

  public static HashingOutputStream sha256() throws NoSuchAlgorithmException {
    return new HashingOutputStream(MessageDigest.getInstance("SHA-256"));
  }

  public static HashingOutputStream sha1() throws NoSuchAlgorithmException {
    return new HashingOutputStream(MessageDigest.getInstance("SHA-1"));
  }

  private HashingOutputStream(MessageDigest digest) {
    this.digest = digest;
  }

  @Override
  public void write(int i) throws IOException {
    digest.update((byte) (i & 0xff));
  }

  @Override
  public void write(byte[] b) throws IOException {
    digest.update(b);
  }

  @Override
  public void write(byte[] b, int off, int len) throws IOException {
    digest.update(b, off, len);
  }

  @Override
  public void flush() throws IOException {
    // ignore
  }

  @Override
  public void close() throws IOException {
    if (calculatedDigest.length == 0) {
      calculatedDigest = this.digest.digest();
    }
  }

  public String toString() {
    return javax.xml.bind.DatatypeConverter.printHexBinary(calculatedDigest);
  }
}
