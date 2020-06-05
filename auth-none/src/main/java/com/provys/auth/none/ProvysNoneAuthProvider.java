package com.provys.auth.none;

import com.provys.auth.api.UserData;
import com.provys.auth.api.UserDataFactory;
import com.provys.common.exception.InternalException;
import java.sql.SQLException;
import java.util.List;
import java.util.Objects;
import oracle.jdbc.pool.OracleDataSource;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.checkerframework.checker.nullness.qual.EnsuresNonNull;
import org.checkerframework.checker.nullness.qual.MonotonicNonNull;
import org.checkerframework.checker.nullness.qual.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.stereotype.Component;

/**
 * This authentication provider ignores supplied credentials (if any) and considers user
 * authenticated. String "GENERIC" is used as database token - this is recognized by ProvysDb and
 * generic connection is used.
 */
@Component
public class ProvysNoneAuthProvider implements AuthenticationProvider {

  private static final Logger LOG = LogManager.getLogger(ProvysNoneAuthProvider.class);
  private static final List<GrantedAuthority> USER_ROLES = AuthorityUtils
      .createAuthorityList("ROLE_USER");

  private static class NoneAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 6379795557131208263L;

    private final UserData principal;

    NoneAuthenticationToken(UserData principal) {
      super(USER_ROLES);
      this.principal = Objects.requireNonNull(principal);
    }

    @Override
    public Object getCredentials() {
      return "";
    }

    @Override
    public Object getPrincipal() {
      return principal;
    }

    @Override
    public boolean equals(@Nullable Object o) {
      if (this == o) {
        return true;
      }
      if (o == null || getClass() != o.getClass()) {
        return false;
      }
      if (!super.equals(o)) {
        return false;
      }
      NoneAuthenticationToken that = (NoneAuthenticationToken) o;
      return principal.equals(that.principal);
    }

    @Override
    public int hashCode() {
      int result = super.hashCode();
      result = 31 * result + principal.hashCode();
      return result;
    }

    @Override
    public String toString() {
      return "NoneAuthenticationToken{"
          + "principal=" + principal
          + ", " + super.toString() + '}';
    }
  }

  private final String provysDbUrl;
  private final String provysDbUser;
  private final String provysDbPwd;
  private final UserDataFactory userDataFactory;
  private volatile @MonotonicNonNull Authentication authenticationResult;

  @Autowired
  ProvysNoneAuthProvider(@Value("${provysdb.url}") String provysDbUrl,
      @Value("${provysdb.user}") String provysDbUser,
      @Value("${provysdb.pwd}") String provysDbPwd, UserDataFactory userDataFactory) {
    this.provysDbUrl = "jdbc:oracle:thin:@" + Objects.requireNonNull(provysDbUrl);
    this.provysDbUser = Objects.requireNonNull(provysDbUser);
    this.provysDbPwd = Objects.requireNonNull(provysDbPwd);
    this.userDataFactory = Objects.requireNonNull(userDataFactory);
  }

  @EnsuresNonNull("authenticationResult")
  private void setAuthenticationResult() {
    try {
      var dataSource = new OracleDataSource();
      dataSource.setURL(provysDbUrl);
      try (var connection = dataSource.getConnection(provysDbUser, provysDbPwd)) {
        authenticationResult = new NoneAuthenticationToken(userDataFactory.getUserData(connection));
        LOG.debug("Initialized authentication result of none auth provider using db {}, user {}",
            provysDbUrl, provysDbUser);
      }
    } catch (SQLException e) {
      throw new InternalException("Failed to initialize Oracle datasource", e);
    }
  }

  private Authentication getAuthenticationResult() {
    if (authenticationResult == null) {
      synchronized (this) {
        if (authenticationResult == null) {
          setAuthenticationResult();
        }
      }
    }
    return authenticationResult;
  }

  @Override
  public Authentication authenticate(Authentication authentication) {
    return getAuthenticationResult();
  }

  @Override
  public boolean supports(Class<?> clazz) {
    return true;
  }

  @Override
  public String toString() {
    return "ProvysNoneAuthProvider{"
        + "provysDbUrl='" + provysDbUrl + '\''
        + ", provysDbUser='" + provysDbUser + '\''
        + ", provysDbPwd='" + provysDbPwd + '\''
        + ", userDataFactory=" + userDataFactory
        + ", authenticationResult=" + authenticationResult
        + '}';
  }
}
