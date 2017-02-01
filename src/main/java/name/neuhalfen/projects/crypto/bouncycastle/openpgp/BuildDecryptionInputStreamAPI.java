package name.neuhalfen.projects.crypto.bouncycastle.openpgp;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting.DecryptWithOpenPGPInputStreamFactory;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting.DecryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting.SignatureValidationStrategies;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting.SignatureValidationStrategy;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;


public class BuildDecryptionInputStreamAPI {


    private InputStream encryptedData;

    private DecryptionConfig decryptionConfig;

    // Signature

    private SignatureValidationStrategy signatureCheckingMode;

    private String expectSignatureFrom;

    BuildDecryptionInputStreamAPI() {

    }

    public Validation withConfig(DecryptionConfig decryptionConfig) {
        BuildDecryptionInputStreamAPI.this.decryptionConfig = decryptionConfig;
        return new Validation();
    }


    public class Decrypt {
        public Validation to(OutputStream os) {
            return new Validation();
        }
    }

    public class Validation {
        public Build andValidateSignatureFrom(String userId) {
            BuildDecryptionInputStreamAPI.this.signatureCheckingMode = SignatureValidationStrategies.requireSpecificSignature();
            BuildDecryptionInputStreamAPI.this.expectSignatureFrom = userId;
            return new Build();
        }

        public Build andValidateSomeoneSigned() {
            BuildDecryptionInputStreamAPI.this.signatureCheckingMode = SignatureValidationStrategies.requireAnySignature();
            return new Build();
        }

        public Build andIgnoreSignatures() {
            BuildDecryptionInputStreamAPI.this.signatureCheckingMode = SignatureValidationStrategies.ignoreSignatures();
            return new Build();
        }
    }

    public class Build {
        public InputStream fromEncryptedInputStream(InputStream encryptedData) throws IOException {
            BuildDecryptionInputStreamAPI.this.encryptedData = encryptedData;

            // FIXME: honor signatureCheckingMode
            final DecryptWithOpenPGPInputStreamFactory pgpInputStreamFactory = DecryptWithOpenPGPInputStreamFactory.create(BuildDecryptionInputStreamAPI.this.decryptionConfig, SignatureValidationStrategies.requireAnySignature());
            return pgpInputStreamFactory.wrapWithDecryptAndVerify(encryptedData);
        }
    }
}
