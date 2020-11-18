package ee.sk.smartid.rest.dao;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class SemanticsIdentifierTest {

    @Test
    public void constructor1() {
        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier("AAA", "BB", "C123");

        assertThat(semanticsIdentifier.getIdentifier(), is("AAABB-C123"));
    }

    @Test
    public void constructor2() {
        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, "BB", "CCC");

        assertThat(semanticsIdentifier.getIdentifier(), is("PNOBB-CCC"));
    }

    @Test
    public void constructor3() {
        SemanticsIdentifier semanticsIdentifier = new SemanticsIdentifier(SemanticsIdentifier.IdentityType.PNO, SemanticsIdentifier.CountryCode.LV, "CCC-DDDDD");

        assertThat(semanticsIdentifier.getIdentifier(), is("PNOLV-CCC-DDDDD"));
    }

}
