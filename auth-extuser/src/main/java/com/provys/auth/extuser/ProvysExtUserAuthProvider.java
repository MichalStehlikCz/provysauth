package com.provys.auth.extuser;

import com.provys.auth.api.ProvysUsernamePasswordAuthProvider;
import com.provys.auth.api.UserDataFactory;
import com.provys.common.exception.InternalException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.SQLException;
import java.util.Base64;
import java.util.List;
import java.util.Objects;
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

@Component
public class ProvysExtUserAuthProvider extends ProvysUsernamePasswordAuthProvider {

  private static final Logger LOG = LogManager.getLogger(ProvysExtUserAuthProvider.class);
  private static final List<GrantedAuthority> USER_ROLES = AuthorityUtils
      .createAuthorityList("ROLE_USER");

  private final String provysDbUrl;
  private final String provysDbUser;
  private final String provysDbPwd;
  private final OracleDataSource dataSource;
  private final UserDataFactory userDataFactory;

  @Autowired
  ProvysExtUserAuthProvider(@Value("${provysdb.url}") String provysDbUrl,
      @Value("${provysdb.user}") String provysDbUser,
      @Value("${provysdb.pwd}") String provysDbPwd,
      @Value("${provysauth.cacheTimeout:900}") long cacheTimeoutSec,
      UserDataFactory userDataFactory) {
    super(cacheTimeoutSec);
    this.provysDbUrl = "jdbc:oracle:thin:@" + Objects.requireNonNull(provysDbUrl);
    this.provysDbUser = Objects.requireNonNull(provysDbUser);
    this.provysDbPwd = Objects.requireNonNull(provysDbPwd);
    try {
      dataSource = new OracleDataSource();
      dataSource.setURL(this.provysDbUrl);
    } catch (SQLException e) {
      throw new InternalException("Failed to initialize Oracle datasource", e);
    }
    this.userDataFactory = userDataFactory;
  }

  private static String createHash(String userName, String password) {
    MessageDigest messageDigest;
    try {
      messageDigest = MessageDigest.getInstance("SHA512");
    } catch (NoSuchAlgorithmException e) {
      throw new InternalException("Algorithm SHA512 not found for password hashing", e);
    }
    return Base64.getEncoder()
        .encodeToString(
            messageDigest.digest((password + userName).getBytes(StandardCharsets.UTF_8)));
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
  protected Authentication authenticate(String userName, String password) {
    try (var connection = dataSource.getConnection(provysDbUser, provysDbPwd)) {
      try (var preparedCall = connection.prepareCall(
          "DECLARE\n"
              + "  l_ShortName_NM VARCHAR2(200) :=?;"
              + "  l_Password VARCHAR2(200) :=?;"
              + "BEGIN\n"
              + "  KEC_User_CP.mp_SetExtUserID_Password(\n"
              + "        p_User_NM => l_ShortName_NM\n"
              + "      , p_Password => l_Password\n"
              + "    );\n"
              + "END;")) {
        preparedCall.setString(1, userName.trim());
        preparedCall.setString(2, createHash(userName, password));
      }
      LOG.debug("Verified user login via extuser (user {}, db {}, dbUser {})", userName,
          provysDbUrl, provysDbUser);
      return new UsernamePasswordAuthenticationToken(
          userDataFactory.getUserData(connection),
          password, USER_ROLES);
    } catch (SQLException e) {
      LOG.debug("User login via ExtUser failed (user {}, db {}, dbUser {}): {}", userName,
          provysDbUrl, provysDbUser, e);
      throw new BadCredentialsException("Invalid username or password " + e.getErrorCode()
          + e.getMessage(), e);
    }
  }

  @Override
  public String toString() {
    return "ProvysExtUserAuthProvider{"
        + "provysDbUrl='" + provysDbUrl + '\''
        + ", provysDbUser='" + provysDbUser + '\''
        + ", " + super.toString() + '}';
  }
}
