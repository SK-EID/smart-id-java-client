package ee.sk.smartid;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;

public class AuthenticationIdentityTest {

    @SuppressWarnings( "deprecation" )
    @Test
    public void setSurName() {
        AuthenticationIdentity authenticationIdentity = new AuthenticationIdentity();
        authenticationIdentity.setSurName("surname1");

        assertThat(authenticationIdentity.getSurname(), is("surname1"));
    }

    @SuppressWarnings( "deprecation" )
    @Test
    public void getSurName() {
        AuthenticationIdentity authenticationIdentity = new AuthenticationIdentity();
        authenticationIdentity.setSurname("surname");

        assertThat(authenticationIdentity.getSurName(), is("surname"));
    }

    @Test
    public void getIdentityCode() {
        AuthenticationIdentity authenticationIdentity = new AuthenticationIdentity();
        authenticationIdentity.setIdentityNumber("identityNumber");

        assertThat(authenticationIdentity.getIdentityCode(), is("identityNumber"));
    }

    @Test
    public void setIdentityCode() {
        AuthenticationIdentity authenticationIdentity = new AuthenticationIdentity();
        authenticationIdentity.setIdentityCode("identityCode");

        assertThat(authenticationIdentity.getIdentityNumber(), is("identityCode"));
    }


}
