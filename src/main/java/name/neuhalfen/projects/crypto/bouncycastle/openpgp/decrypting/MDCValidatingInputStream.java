package name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import javax.annotation.Nonnull;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;

@SuppressWarnings("PMD.ShortVariable")
final class MDCValidatingInputStream extends FilterInputStream {

  private static final org.slf4j.Logger LOGGER = org.slf4j.LoggerFactory
      .getLogger(MDCValidatingInputStream.class);

  /**
   * Creates a <code>MDCValidatingInputStream</code> by assigning the  argument
   * <code>inputStream</code> to the field <code>this.inputStream</code> and <code>pbe</code> to <code>this.pbe</code> so as to remember it for
   * later use.
   *
   * @param inputStream the underlying input stream
   * @param pbe the pgp public key encrypted data to verify message integrity
   */

  private final PGPPublicKeyEncryptedData pbe;

  MDCValidatingInputStream(InputStream inputStream, PGPPublicKeyEncryptedData pbe) {
    super(inputStream);
    this.pbe = pbe;
  }

  @Override
  public int read() throws IOException {
    final int data = super.read();
    final boolean endOfStream = data == -1;
    if (endOfStream) {
      validateMDC();
    }
    return data;
  }

  @Override
  public int read(@Nonnull byte[] b) throws IOException {
    return read(b, 0, b.length);
  }

  @Override
  public int read(@Nonnull byte[] b, int off, int len) throws IOException {
    final int read = super.read(b, off, len);

    final boolean endOfStream = read == -1;
    if (endOfStream) {
      validateMDC();
    }
    return read;
  }

  /**
   * Checks MDC if present.
   * If stream is not encrypted, returns directly
   *
   * @throws IOException Error while reading input stream or if MDC fails
   */
  private void validateMDC() throws IOException {
    if (pbe == null) { return; }
    try {
      if (pbe.isIntegrityProtected()) {
        if (!pbe.verify()) {
          throw new PGPException("Data is integrity protected but integrity check failed");
        }
      } else {
        LOGGER.trace("Data integrity is not checked");
      }
    } catch (PGPException ex) {
      throw new IOException("Error while validating MDC", ex);
    }

  }

  @Override
  public long skip(long n) throws IOException {
    throw new UnsupportedOperationException("Skipping not supported");
  }

  @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
  @Override
  public synchronized void mark(int readlimit) {
    throw new UnsupportedOperationException("mark not supported");
  }

  @SuppressWarnings("PMD.AvoidSynchronizedAtMethodLevel")
  @Override
  public synchronized void reset() throws IOException {
    throw new UnsupportedOperationException("reset not supported");
  }

  @Override
  public boolean markSupported() {
    return false;
  }
}
