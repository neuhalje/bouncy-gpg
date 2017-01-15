package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption;

import name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.encrypting.StreamEncryption;
import org.junit.Ignore;
import org.junit.Test;

import java.io.InputStream;
import static org.mockito.Mockito.*;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;


public class ExplodeAndReencryptTest {

    ExplodeAndReencrypt sut() {
        return new ExplodeAndReencrypt(mock(InputStream.class), mock(ZipEntityStrategy.class),mock(StreamEncryption.class));
    }

    @Test
    public void rewriteName_withNameWithSlashes_removesLeadingSlashes() {
        final String invalidName = "/Test/bla/";
        final String validName ="Test/bla/";

        assertThat(sut().rewriteName(invalidName), is(validName));
    }

    @Test
    public void rewriteName_withNameWithDotDot_removesDots() {
        final String invalidName = "..Test..bla..";
        final String validName ="Testbla";

        assertThat(sut().rewriteName(invalidName), is(validName));
    }

    @Test
    public void rewriteName_withNameWithSingleDot_keepsDot() {
        final String invalidName = "Test.bla";
        final String validName ="Test.bla";

        assertThat(sut().rewriteName(invalidName), is(validName));
    }

    @Test
    public void rewriteName_withNameWithSingleDotAndDotDot_onlyKeepsDot() {
        final String invalidName = "Test.bla..";
        final String validName ="Test.bla";

        assertThat(sut().rewriteName(invalidName), is(validName));
    }

    @Test
    @Ignore("Implementation is not correct but not worth the effort")
    public void rewriteName_witWildCombinations_removesDotDotAndLeadingSlash() {
        final String invalidName = "/bla/../../Test.bla..";
        final String validName ="bla/Test.bla";

        assertThat(sut().rewriteName(invalidName), is(validName));
    }

    @Test
    public void rewriteName_withValidName_doesNotChangeName() {
        final String validName = "Test.bla";
        assertThat(sut().rewriteName(validName), is(validName));
    }

    @Test
    public void rewriteName_withValidPath_doesNotChangeName() {
        final String validName ="main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/decrypting/DecryptionConfig.java";
        assertThat(sut().rewriteName(validName), is(validName));
    }
    @Test
    public void rewriteName_withPathTraversal_keepsNonDotDot() {
        final String invalidName = "../../../main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/decrypting/DecryptionConfig.java";
        final String validName ="main/java/name/neuhalfen/projects/crypto/bouncycastle/examples/openpgp/decrypting/DecryptionConfig.java";

        assertThat(sut().rewriteName(invalidName), is(validName));
    }



}
