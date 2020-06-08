package com.provys.auth.mock;

import com.provys.auth.api.ProvysUserData;
import com.provys.common.crypt.DtEncryptedString;
import com.provys.common.datatype.DtUid;
import java.util.Map;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Used to create ProvysMockAuthProvider bean instance for AuthProviderLookupTest.
 */
@Configuration
public class MockAuthProviderFactory {

  private static final UsernamePasswordPair USERNAME_PASSWORD
      = new UsernamePasswordPair("user", "pwd");
  private static final UsernamePasswordPair USERNAME_PASSWORD0
      = new UsernamePasswordPair("user0", "pwd0");

  static UsernamePasswordPair getUsernamePassword() {
    return USERNAME_PASSWORD;
  }

  static UsernamePasswordPair getUsernamePassword0() {
    return USERNAME_PASSWORD0;
  }

  @Bean
  MockAuthProvider mockAuthProvider() {
    return new MockAuthProvider(
        Map.of(getUsernamePassword(),
            ProvysUserData.of(DtUid.valueOf("1"), "USER", "User",
                DtEncryptedString.valueOf("TOKEN"))));
  }

  @Bean
  MockAuthProvider mockAuthProvider0() {
    return new MockAuthProvider(
        Map.of(getUsernamePassword0(),
            ProvysUserData.of(DtUid.valueOf("2"), "USER0", "User0",
                DtEncryptedString.valueOf("TOKEN0"))));
  }
}
