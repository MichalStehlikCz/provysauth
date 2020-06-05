package com.provys.auth.oracle;

import com.provys.auth.api.ProvysUsernamePasswordAuthProvider;
import com.provys.auth.api.UserDataFactory;
import com.provys.common.exception.InternalException;
import java.sql.SQLException;
import java.util.List;
import java.util.Objects;
import javax.sql.DataSource;
import oracle.jdbc.pool.OracleDataSource;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Component;

/**
 * Authentication provider that authenticates username + password pair by connecting to Oracle
 * database using these credentials. Caches result for defined period of time to speed up repeated
 * authentication using the same credentials.
 */
@Component
public class ProvysOracleAuthProvider extends ProvysUsernamePasswordAuthProvider {

  private static final Logger LOG = LogManager.getLogger(ProvysOracleAuthProvider.class);
  private static final List<GrantedAuthority> USER_ROLES = AuthorityUtils
      .createAuthorityList("ROLE_USER");

  private final String provysDbUrl;
  private final DataSource dataSource;
  private final UserDataFactory userDataFactory;

  @Autowired
  ProvysOracleAuthProvider(@Value("${provysdb.url}") String provysDbUrl,
      @Value("${provysauth.cacheTimeout:900}") long cacheTimeoutSec,
      UserDataFactory userDataFactory) {
    super(cacheTimeoutSec);
    this.provysDbUrl = "jdbc:oracle:thin:@" + Objects.requireNonNull(provysDbUrl);
    try {
      dataSource = new OracleDataSource();
      ((OracleDataSource) dataSource).setURL(this.provysDbUrl);
    } catch (SQLException e) {
      throw new InternalException("Failed to initialize Oracle datasource", e);
    }
    this.userDataFactory = Objects.requireNonNull(userDataFactory);
  }

  ProvysOracleAuthProvider(String provysDbUrl, DataSource dataSource, long cacheTimeoutSec,
      UserDataFactory userDataFactory) {
    super(cacheTimeoutSec);
    this.provysDbUrl = "jdbc:oracle:thin:@" + Objects.requireNonNull(provysDbUrl);
    this.dataSource = Objects.requireNonNull(dataSource);
    this.userDataFactory = Objects.requireNonNull(userDataFactory);
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
  @Override
  protected Authentication doAuthenticate(String userName, String password) {
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

  @Override
  public String toString() {
    return "ProvysOracleAuthProvider{"
        + "provysDbUrl='" + provysDbUrl + '\''
        + '}';
  }
}
