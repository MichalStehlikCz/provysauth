package com.provys.auth.oracle;

import com.provys.auth.api.UserDataFactory;
import com.provys.common.datatype.DtUid;
import com.provys.common.exception.InternalException;
import java.sql.SQLException;
import java.sql.Types;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import oracle.jdbc.pool.OracleDataSource;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Component;

@Component
public class ProvysOracleAuthProvider implements AuthenticationProvider {

  private static final Logger LOG = LogManager.getLogger(ProvysOracleAuthProvider.class);
  private static final List<GrantedAuthority> USER_ROLES = AuthorityUtils
      .createAuthorityList("ROLE_USER");

  private final String provysDbUrl;
  private final OracleDataSource dataSource;
  private final UserDataFactory userDataFactory;
  private final long cacheTimeoutMs;
  private final Map<String, CacheValue> cache = new ConcurrentHashMap<>(10);

  @Autowired
  ProvysOracleAuthProvider(@Value("${provysdb.url}") String provysDbUrl,
      @Value("${provysauth.cacheTimeout:900}") long cacheTimeoutSec,
      UserDataFactory userDataFactory) {
    this.provysDbUrl = "jdbc:oracle:thin:@" + provysDbUrl;
    try {
      dataSource = new OracleDataSource();
      dataSource.setURL(this.provysDbUrl);
    } catch (SQLException e) {
      throw new InternalException("Failed to initialize Oracle datasource", e);
    }
    this.cacheTimeoutMs = 1000L * cacheTimeoutSec;
    this.userDataFactory = userDataFactory;
  }

  /**
   * Look-up cached value for given username / password combo.
   *
   * @param userName is user name being authenticated
   * @param password is associated password being verified
   * @return authentication token if successful, empty optional if not validated against cache
   */
  private Optional<Authentication> cacheLookup(String userName, String password) {
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
   * Validate username / password combo against database.
   *
   * @param userName is username to be used for connection
   * @param password is password to be used for connection
   * @return authentication token
   * @throws BadCredentialsException if login fails using given username / password combination
   * @throws InternalException       if connection to database fails for other reasons
   */
  private Authentication dbAuthenticate(String userName, String password) {
    try (var connection = dataSource.getConnection(userName, password)) {
      LOG.debug("Verified user login via database (user {}, db {})", userName, provysDbUrl);
      return new UsernamePasswordAuthenticationToken(
          userDataFactory.getUserData(connection),
          password, USER_ROLES);
    } catch (SQLException e) {
      LOG.debug("User login via database failed (user {}, db {}): {}", userName, provysDbUrl, e);
      throw new BadCredentialsException("Invalid username or password " + e.getErrorCode()
          + e.getMessage(), e);
    }
  }

  private Authentication dbAuthenticateAndCache(String userName, String password) {
    var result = dbAuthenticate(userName, password);
    cache.put(userName,
        new CacheValue(System.currentTimeMillis() + cacheTimeoutMs, password, result));
    return result;
  }

  @Override
  public Authentication authenticate(Authentication authentication) {
    var token = (UsernamePasswordAuthenticationToken) authentication;
    var userName = token.getName();
    var password = (String) token.getCredentials();
    return cacheLookup(userName, password)
        .orElseGet(() -> dbAuthenticateAndCache(userName, password));
  }

  @Override
  public boolean supports(Class<?> clazz) {
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(clazz);
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

  @Override
  public String toString() {
    return "ProvysOracleAuthProvider{"
        + "provysDbUrl='" + provysDbUrl + '\''
        + '}';
  }
}
