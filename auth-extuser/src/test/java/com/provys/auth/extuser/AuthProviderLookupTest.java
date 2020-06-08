package com.provys.auth.extuser;

import static org.assertj.core.api.Assertions.assertThat;

import com.provys.auth.api.AuthProviderLookup;
import java.util.Objects;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
public class AuthProviderLookupTest {

  private final AuthProviderLookup authProviderLookup;

  @Autowired
  AuthProviderLookupTest(AuthProviderLookup authProviderLookup) {
    this.authProviderLookup = Objects.requireNonNull(authProviderLookup);
  }

  @Test
  void getAuthProviderTest() {
    assertThat(authProviderLookup.getAuthProvider("EXTUSER"))
        .isInstanceOf(ExtUserAuthProvider.class);
  }
}
