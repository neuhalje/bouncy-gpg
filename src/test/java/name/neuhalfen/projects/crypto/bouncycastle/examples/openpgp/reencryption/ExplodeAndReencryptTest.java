package name.neuhalfen.projects.crypto.bouncycastle.examples.openpgp.reencryption;

import org.junit.Test;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;


public class ExplodeAndReencryptTest {

    ExplodeAndReencrypt sut() {
        return new ExplodeAndReencrypt(null,null,null);
    }

    @Test
    public void rewriteName_withNameWithSlashes_removesSlashes() {
        final String invalidName = "/Test/bla/";
        final String validName ="Testbla";

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
    public void rewriteName_witWildCombinations_keepsValids() {
        final String invalidName = "/bla/../../Test.bla..";
        final String validName ="blaTest.bla";

        assertThat(sut().rewriteName(invalidName), is(validName));
    }

    @Test
    public void rewriteName_withValidName_doesNotChangeName() {
        final String validName = "Test.bla";
        assertThat(sut().rewriteName(validName), is(validName));
    }

}
