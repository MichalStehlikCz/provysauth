package com.provys.auth.oracle;

import com.provys.auth.api.ProvysUserData;
import com.provys.common.datatype.DtUid;
import com.provys.common.exception.InternalException;
import java.sql.SQLException;
import java.sql.Types;
import java.util.List;
import oracle.jdbc.pool.OracleDataSource;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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

  ProvysOracleAuthProvider(@Value("${provysdb.url}") String provysDbUrl) {
    this.provysDbUrl = "jdbc:oracle:thin:@" + provysDbUrl;
    try {
      dataSource = new OracleDataSource();
      dataSource.setURL(this.provysDbUrl);
    } catch (SQLException e) {
      throw new InternalException("Failed to initialize Oracle datasource", e);
    }
  }

  @Override
  public Authentication authenticate(Authentication authentication) {
    var token = (UsernamePasswordAuthenticationToken) authentication;
    var userName = token.getName();
    var password = (String) token.getCredentials();
    try (var connection = dataSource.getConnection(userName, password)) {
      try (var statement = connection.prepareCall("BEGIN\n"
          + "  :c_User_ID:=KER_User_EP.mfw_GetUserID;\n"
          + "  SELECT\n"
          + "        usr.shortname_nm\n"
          + "      , usr.fullname\n"
          + "    INTO\n"
          + "        :c_ShortName_NM"
          + "      , :c_FullName\n"
          + "    FROM\n"
          + "        ker_receiver_tb receiver\n"
          + "    WHERE\n"
          + "          (receiver_id=:c_User_ID)\n"
          + "    ;"
          + "  :c_Token:=KER_User_PG.mf_CreateToken(SYSDATE+1);"
          + "END;")) {
        statement.registerOutParameter("c_User_ID", Types.NUMERIC);
        statement.registerOutParameter("c_ShortName_NM", Types.VARCHAR);
        statement.registerOutParameter("c_FullName", Types.VARCHAR);
        statement.registerOutParameter("c_Token", Types.VARCHAR);
        statement.execute();
        LOG.debug("Verified user login via database (user {}, db {})", userName, provysDbUrl);
        var user = new ProvysUserData(
            DtUid.valueOf(statement.getBigDecimal("c_User_ID")),
            statement.getString("c_ShortName_NM"),
            statement.getString("c_FullName"),
            statement.getString("c_Token"));
        return new UsernamePasswordAuthenticationToken(user, password, USER_ROLES);
      }
    } catch (SQLException e) {
      LOG.debug("User login via database failed (user {}, db {}): {}", userName, provysDbUrl, e);
      throw new BadCredentialsException("Invalid username or password " + e.getErrorCode()
          + e.getMessage(), e);
    }
  }

  @Override
  public boolean supports(Class<?> aClass) {
    return UsernamePasswordAuthenticationToken.class.isAssignableFrom(aClass);
  }

  @Override
  public String toString() {
    return "ProvysOracleAuthProvider{"
        + "provysDbUrl='" + provysDbUrl + '\''
        + '}';
  }
}
