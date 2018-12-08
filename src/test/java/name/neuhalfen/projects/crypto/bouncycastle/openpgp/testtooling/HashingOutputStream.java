package name.neuhalfen.projects.crypto.bouncycastle.openpgp.testtooling;

import static name.neuhalfen.projects.crypto.internal.DataFormatter.byteArrayToHexString;

import java.io.IOException;
import java.io.OutputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import org.bouncycastle.jcajce.provider.digest.SHA3.Digest256;
import org.bouncycastle.jcajce.provider.digest.SHA3.Digest512;

/**
 * Hash everything written into this stream. Used in tests to verify large datasets can be decrypted
 * reliably. <p> The hash is made available via toString and calculated on close.
 */
public class HashingOutputStream extends OutputStream {

  private final MessageDigest digest;

  private byte[] calculatedDigest = {};

  private HashingOutputStream(MessageDigest digest) {
    this.digest = digest;
  }

  public static HashingOutputStream sha256() throws NoSuchAlgorithmException {
    return new HashingOutputStream(MessageDigest.getInstance("SHA-256"));
  }

  public static HashingOutputStream sha512_Oracle()
      throws NoSuchAlgorithmException, NoSuchProviderException {
    final MessageDigest instance = MessageDigest.getInstance("SHA-512", "SUN");
    return new HashingOutputStream(instance);
  }

  public static HashingOutputStream sha512_BC()
      throws NoSuchAlgorithmException, NoSuchProviderException {
    return new HashingOutputStream(MessageDigest.getInstance("SHA-512", "BC"));
  }

  public static HashingOutputStream sha1() throws NoSuchAlgorithmException {
    return new HashingOutputStream(MessageDigest.getInstance("SHA-1"));
  }


  public static HashingOutputStream sha3_256() throws NoSuchAlgorithmException {
    final MessageDigest digest256 = new Digest256();
    return new HashingOutputStream(digest256);
  }

  public static HashingOutputStream sha3_512() throws NoSuchAlgorithmException {
    final MessageDigest digest512 = new Digest512();
    return new HashingOutputStream(digest512);
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
    return byteArrayToHexString(calculatedDigest);
  }
}
