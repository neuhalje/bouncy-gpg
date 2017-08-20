package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Hash everything read from the wrapped stream. Used in tests to verify large datasets can be
 * decrypted reliably. <p> Does not support mark & friends.
 */
public class HashingInputStream extends FilterInputStream {

  private final MessageDigest digest;

  private byte[] calculatedDigest = {};

  public static HashingInputStream sha256(InputStream src) throws NoSuchAlgorithmException {
    return new HashingInputStream(MessageDigest.getInstance("SHA-256"), src);
  }

  public static HashingInputStream sha1(InputStream src) throws NoSuchAlgorithmException {
    return new HashingInputStream(MessageDigest.getInstance("SHA-1"), src);
  }

  private HashingInputStream(MessageDigest digest, InputStream src) {
    super(src);
    this.digest = digest;
  }

  @Override
  public int read() throws IOException {
    int i = super.read();
    if (i != -1) {
      digest.update((byte) (i & 0xff));
    }
    return i;
  }

  @Override
  public int read(byte[] b) throws IOException {
    // FilterInputStream::read(byte[]) calls read(byte[],int,int)
    // So we do not need to update then hash here
    return super.read(b);
  }

  @Override
  public int read(byte[] b, int off, int len) throws IOException {
    int i = super.read(b, off, len);
    if (i != -1) {
      digest.update(b, off, i);
    }
    return i;
  }

  @Override
  public synchronized void mark(int readlimit) {
    throw new RuntimeException("reset not supported");
  }

  @Override
  public synchronized void reset() throws IOException {
    throw new IOException("reset not supported");
  }

  @Override
  public boolean markSupported() {
    return false;
  }

  @Override
  public void close() throws IOException {
    super.close();

    if (calculatedDigest.length == 0) {
      calculatedDigest = this.digest.digest();
    }
  }

  public String toString() {
    return javax.xml.bind.DatatypeConverter.printHexBinary(calculatedDigest);
  }
}
