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

  @Bean
  ProvysMockAuthProvider provysMockAuthProvider() {
    return new ProvysMockAuthProvider(
        Map.of(new UsernamePasswordPair("user", "pwd"),
            ProvysUserData.of(DtUid.valueOf("1"), "USER", "User",
                DtEncryptedString.valueOf("TOKEN"))));
  }
}
