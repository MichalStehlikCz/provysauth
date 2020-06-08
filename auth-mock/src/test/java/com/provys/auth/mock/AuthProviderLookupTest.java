package com.provys.auth.mock;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

import com.provys.auth.api.AuthProviderLookup;
import java.util.Objects;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;

@SpringBootTest
public class AuthProviderLookupTest {

  private final AuthProviderLookup authProviderLookup;

  private static UsernamePasswordAuthenticationToken getToken(UsernamePasswordPair pair) {
    return new UsernamePasswordAuthenticationToken(pair.getUserName(), pair.getPassword());
  }

  @Autowired
  AuthProviderLookupTest(AuthProviderLookup authProviderLookup) {
    this.authProviderLookup = Objects.requireNonNull(authProviderLookup);
  }

  @Test
  void getAuthProviderTest() {
    var provider = authProviderLookup.getAuthProvider("MOCK");
    var token = getToken(MockAuthProviderFactory.getUsernamePassword());
    var token0 = getToken(MockAuthProviderFactory.getUsernamePassword0());
    assertThat(provider)
        .isInstanceOf(MockAuthProvider.class);
    assertThatCode(() -> provider.authenticate(token))
        .doesNotThrowAnyException();
    assertThatCode(() -> provider.authenticate(token0))
        .isInstanceOf(BadCredentialsException.class);
  }

  @Test
  void getAuthProvider0Test() {
    var provider = authProviderLookup.getAuthProvider("MOCK$0");
    var token = getToken(MockAuthProviderFactory.getUsernamePassword());
    var token0 = getToken(MockAuthProviderFactory.getUsernamePassword0());
    assertThat(provider)
        .isInstanceOf(MockAuthProvider.class);
    assertThatCode(() -> provider.authenticate(token))
        .isInstanceOf(BadCredentialsException.class);
    assertThatCode(() -> provider.authenticate(token0))
        .doesNotThrowAnyException();
  }
}
