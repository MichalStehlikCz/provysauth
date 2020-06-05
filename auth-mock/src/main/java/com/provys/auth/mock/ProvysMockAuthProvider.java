package com.provys.auth.mock;

import com.provys.auth.api.UserData;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.stream.Collectors;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

/**
 * This authentication provider is only to be used for testing. It allows to set up predefined
 * answers for username / password authentication requests. As set-up is required, it is not marked
 * as component, instead, user is responsible to set up bean via factory, that will define these
 * answers
 */
public final class ProvysMockAuthProvider implements AuthenticationProvider {

  private static final List<GrantedAuthority> USER_ROLES = AuthorityUtils
      .createAuthorityList("ROLE_USER");

  private final Map<UsernamePasswordPair, Authentication> authentications;

  /**
   * Create mock authentication provider, successfully authenticates supplied username + password
   * pairs.
   *
   * @param userData is map of credentials and corresponding user data items
   */
  public ProvysMockAuthProvider(Map<UsernamePasswordPair, UserData> userData) {
    this.authentications = userData.entrySet().stream()
        .map(entry -> Map.entry(entry.getKey(),
            new UsernamePasswordAuthenticationToken(
                entry.getValue(), entry.getKey().getPassword(), USER_ROLES)))
        .collect(Collectors.toUnmodifiableMap(Entry::getKey, Entry::getValue));
  }

  @Override
  public Authentication authenticate(Authentication authentication) {
    var token = (UsernamePasswordAuthenticationToken) authentication;
    var userName = token.getName();
    var password = (String) token.getCredentials();
    var usernamePassword = new UsernamePasswordPair(userName, password);
    var result = authentications.get(usernamePassword);
    if (result == null) {
      throw new BadCredentialsException("Invalid username / password");
    }
    return result;
  }

  @Override
  public boolean supports(Class<?> clazz) {
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(clazz);
  }

  @Override
  public String toString() {
    return "ProvysMockAuthProvider{"
        + "authentications=" + authentications
        + '}';
  }
}
