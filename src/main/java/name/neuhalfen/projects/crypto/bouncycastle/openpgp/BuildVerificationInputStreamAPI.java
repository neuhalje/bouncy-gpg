package name.neuhalfen.projects.crypto.bouncycastle.openpgp;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting.DecryptionConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting.SignatureValidationStrategies;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.decrypting.SignatureValidationStrategy;

import java.io.InputStream;

public class BuildVerificationInputStreamAPI {
    private InputStream signedData;

    private DecryptionConfig decryptionConfig;

    // Signature

    private SignatureValidationStrategy signatureCheckingMode;

    private String expectSignatureFrom;

    BuildVerificationInputStreamAPI() {
    }

    public Validation withConfig(DecryptionConfig decryptionConfig) {
        BuildVerificationInputStreamAPI.this.decryptionConfig = decryptionConfig;
        return new Validation();
    }


    public class Validation {
        public Validate andValidateSignatureFrom(String userId) {
            BuildVerificationInputStreamAPI.this.signatureCheckingMode = SignatureValidationStrategies.requireSpecificSignature();
            BuildVerificationInputStreamAPI.this.expectSignatureFrom = userId;
            return new Validate();
        }

        public Validate andValidateSomeoneSigned() {
            BuildVerificationInputStreamAPI.this.signatureCheckingMode = SignatureValidationStrategies.requireAnySignature();
            return new Validate();
        }

        public Validate andIgnoreSignatures() {
            BuildVerificationInputStreamAPI.this.signatureCheckingMode = SignatureValidationStrategies.ignoreSignatures();
            return new Validate();
        }
    }

    public class Validate {
        public boolean forSignedInputStream(InputStream signedData) {
            // TODO Implement
            BuildVerificationInputStreamAPI.this.signedData = signedData;
            throw new AssertionError();
        }
    }
}
