package name.neuhalfen.projects.crypto.internal;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.emptyIterable;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Test;

public class SetUtilsTest {

  @Test
  public void noArgsCall_yields_emptySet() {
    assertThat(SetUtils.unmodifiableSet(), is(emptyIterable()));
  }


  @Test
  public void oneArgCall_yields_oneArgSet() {
    assertThat(SetUtils.unmodifiableSet("one"), containsInAnyOrder("one"));
  }

  @Test
  public void duplicateArgCall_yields_oneArgSet() {
    assertThat(SetUtils.unmodifiableSet("one", "one"), containsInAnyOrder("one"));
  }

  @Test
  public void primitiveArgCall_yields_oneArgSet() {
    assertThat(SetUtils.unmodifiableSet(1), containsInAnyOrder(1));
  }
}