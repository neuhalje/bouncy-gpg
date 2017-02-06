package name.neuhalfen.projects.crypto.bouncycastle.openpgp;

import name.neuhalfen.projects.crypto.bouncycastle.openpgp.keys.KeyringConfig;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignatureValidationStrategies;
import name.neuhalfen.projects.crypto.bouncycastle.openpgp.validation.SignatureValidationStrategy;

import java.io.InputStream;
import java.util.Collection;

public class BuildVerificationInputStreamAPI {
    private InputStream signedData;

    private KeyringConfig keyringConfig;

    // Signature

    private SignatureValidationStrategy signatureCheckingMode;

    BuildVerificationInputStreamAPI() {
    }

    public Validation withConfig(KeyringConfig decryptionConfig) {
        BuildVerificationInputStreamAPI.this.keyringConfig = decryptionConfig;
        return new Validation();
    }


    public class Validation {
        public Validate andValidateSignatureFrom(Collection<Long> publicKeyIds) {
            BuildVerificationInputStreamAPI.this.signatureCheckingMode = SignatureValidationStrategies.requireSignatureFromAllKeys(publicKeyIds);
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
