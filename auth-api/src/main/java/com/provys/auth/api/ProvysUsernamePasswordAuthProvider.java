package com.provys.auth.api;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * Common ancestor for username / password authentication providers. Implements credential caching.
 */
public abstract class ProvysUsernamePasswordAuthProvider implements AuthenticationProvider {

  private final long cacheTimeoutMs;
  private final Map<String, CacheValue> cache = new ConcurrentHashMap<>(10);

  /**
   * Create new username password authentication provider with specified cache timeout.
   *
   * @param cacheTimeoutSec cache timeout in seconds
   */
  public ProvysUsernamePasswordAuthProvider(long cacheTimeoutSec) {
    this.cacheTimeoutMs = 1000L * cacheTimeoutSec;
  }

  private static final class CacheValue {

    private final long validUntil;
    private final String password;
    private final Authentication authToken;

    CacheValue(long validUntil, String password, Authentication authToken) {
      this.validUntil = validUntil;
      this.password = password;
      this.authToken = authToken;
    }

    boolean isValid() {
      return validUntil > System.currentTimeMillis();
    }

    boolean passwordMatch(String checkPassword) {
      return password.equals(checkPassword);
    }

    @Override
    public String toString() {
      return "CacheValue{"
          + "validUntil=" + validUntil
          // password is intentionally omitted
          + "authToken='" + authToken + '\''
          + '}';
    }
  }

  /**
   * Look-up cached value for given username / password combo.
   *
   * @param userName is user name being authenticated
   * @param password is associated password being verified
   * @return authentication token if successful, empty optional if not validated against cache
   */
  protected Optional<Authentication> cacheLookup(String userName, String password) {
    var value = cache.get(userName);
    if (value == null) {
      // no entry in cache
      return Optional.empty();
    }
    if (!value.isValid()) {
      // cache entry expired - we will clear the entry and return not found
      cache.remove(userName);
      return Optional.empty();
    }
    if (!value.passwordMatch(password)) {
      // no password match - we will try regular authentication (password might have been changed)
      return Optional.empty();
    }
    return Optional.of(value.authToken);
  }

  /**
   * Store successful authentication result to cache.
   *
   * @param userName is username used for login
   * @param password is password used for login
   * @param authToken authentication token created during successful authentication
   */
  protected void cache(String userName, String password, Authentication authToken) {
    cache.put(userName,
        new CacheValue(System.currentTimeMillis() + cacheTimeoutMs, password, authToken));
  }

  /**
   * Does actual authentication.
   *
   * @param userName is username used for login
   * @param password is password used for login
   * @return authentication token if successful
   */
  protected abstract Authentication authenticate(String userName, String password);

  /**
   * Do actual authentication and cache result.
   *
   * @param userName is username used for login
   * @param password is password used for login
   * @return authentication token if successful
   */
  protected Authentication authenticateAndCache(String userName, String password) {
    var result = authenticate(userName, password);
    cache(userName, password, result);
    return result;
  }

  @Override
  public Authentication authenticate(Authentication authentication) {
    var token = (UsernamePasswordAuthenticationToken) authentication;
    var userName = token.getName();
    var password = (String) token.getCredentials();
    return cacheLookup(userName, password)
        .orElseGet(() -> authenticateAndCache(userName, password));
  }

  @Override
  public boolean supports(Class<?> clazz) {
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(clazz);
  }

  @Override
  public String toString() {
    return "ProvysUsernamePasswordAuthProvider{"
        + "cacheTimeoutMs=" + cacheTimeoutMs
        + ", cache=" + cache
        + '}';
  }
}
