package com.provys.auth.api;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.provys.common.crypt.DtEncryptedString;
import com.provys.common.datatype.DtUid;
import java.math.BigInteger;
import java.security.Principal;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

public class ProvysUsernamePasswordAuthProviderTest {

  private static class ProvysUsernamePasswordAuthProviderImpl
      extends ProvysUsernamePasswordAuthProvider {

    private static final List<GrantedAuthority> USER_ROLES = AuthorityUtils
        .createAuthorityList("ROLE_USER");

    /** Counter incremented each time actual authentication is performed */
    private int auths = 0;

    /**
     * Create new username password authentication provider with specified cache timeout.
     *
     * @param cacheTimeoutSec cache timeout in seconds
     */
    ProvysUsernamePasswordAuthProviderImpl(long cacheTimeoutSec) {
      super(cacheTimeoutSec);
    }

    /**
     * Value of field auths.
     *
     * @return value of field auths
     */
    public int getAuths() {
      return auths;
    }

    @Override
    protected Authentication doAuthenticate(String userName, String password) {
      auths++;
      if (!password.equals(userName + "PWD")) {
        throw new BadCredentialsException("Invalid username / password");
      }
      return new UsernamePasswordAuthenticationToken(new ProvysUserData(DtUid.valueOf("1"),
          userName, userName, DtEncryptedString.valueOf("TOKEN")), password, USER_ROLES);
    }
  }

  private static Authentication setUpToken(String userName, String password) {
    var authentication = mock(UsernamePasswordAuthenticationToken.class);
    var principal = mock(Principal.class);
    when(authentication.getPrincipal()).thenReturn(principal);
    when(principal.getName()).thenReturn(userName);
    when(authentication.getName()).thenReturn(userName);
    when(authentication.getCredentials()).thenReturn(password);
    return authentication;
  }

  @Test
  void authenticate() throws InterruptedException {
    var authProvider = new ProvysUsernamePasswordAuthProviderImpl(1);
    // set up correct credentials
    var userName1 = "USER1";
    var password1 = "USER1PWD";
    var userName2 = "USER2";
    var password2 = "USER2PWD";
    // first auth1 - should do authentication
    var authentication1 = setUpToken(userName1, password1);
    var result1 = authProvider.authenticate(authentication1);
    assertThat(result1.getName()).isEqualTo(userName1);
    assertThat(authProvider.getAuths()).isEqualTo(1);
    // auth2 - should do authentication
    var authentication2 = setUpToken(userName2, password2);
    var result2 = authProvider.authenticate(authentication2);
    assertThat(result2.getName()).isEqualTo(userName2);;
    assertThat(authProvider.getAuths()).isEqualTo(2);
    // wrong auth1 - should NOT use cache
    var authentication3 = setUpToken(userName1, password2);
    assertThatCode(() -> authProvider.authenticate(authentication3))
        .isInstanceOf(BadCredentialsException.class);
    assertThat(authProvider.getAuths()).isEqualTo(3);
    // second auth1 - should use cache
    var authentication4 = setUpToken(userName1, password1);
    var result4 = authProvider.authenticate(authentication4);
    assertThat(result4.getName()).isEqualTo(userName1);
    assertThat(authProvider.getAuths()).isEqualTo(3); // cache used, no auth
    // wait for cache expiration and repeat
    Thread.sleep(2000);
    var authentication5 = setUpToken(userName1, password1);
    var result5 = authProvider.authenticate(authentication5);
    assertThat(result5.getName()).isEqualTo(userName1);;
    assertThat(authProvider.getAuths()).isEqualTo(4); // cache expired
  }

  @Test
  void supportsPositiveTest() {
    var authProvider = new ProvysUsernamePasswordAuthProviderImpl(10);
    assertThat(authProvider.supports(UsernamePasswordAuthenticationToken.class)).isTrue();
  }

  @Test
  void supportsNegativeTest() {
    var authProvider = new ProvysUsernamePasswordAuthProviderImpl(10);
    assertThat(authProvider.supports(AbstractAuthenticationToken.class)).isFalse();
  }
}
