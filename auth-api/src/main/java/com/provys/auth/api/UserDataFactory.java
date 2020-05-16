package com.provys.auth.api;

import com.provys.common.datatype.DtUid;
import com.provys.common.exception.InternalException;
import java.math.BigDecimal;
import java.sql.SQLException;
import java.sql.Types;
import oracle.jdbc.pool.OracleDataSource;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.checkerframework.checker.nullness.qual.Nullable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/**
 * Factory that create UserData based on supplied Id. Uses database look-up
 */
@Component
public final class UserDataFactory {

  private static final Logger LOG = LogManager.getLogger(UserDataFactory.class);

  private final String provysDbUrl;
  private final String provysDbUser;
  private final String provysDbPwd;
  private final OracleDataSource dataSource;

  @Autowired
  public UserDataFactory(@Value("${provysdb.url}") String provysDbUrl,
      @Value("${provysdb.user}") String provysDbUser,
      @Value("${provysdb.pwd}") String provysDbPwd) {
    this.provysDbUrl = "jdbc:oracle:thin:@" + provysDbUrl;
    this.provysDbUser = provysDbUser;
    this.provysDbPwd = provysDbPwd;
    try {
      dataSource = new OracleDataSource();
      dataSource.setURL(this.provysDbUrl);
    } catch (SQLException e) {
      throw new InternalException("Failed to initialize Oracle datasource", e);
    }
  }

  public UserData getUserData(DtUid userId) {
    try (var connection = dataSource.getConnection(provysDbUser, provysDbPwd)) {
      try (var statement = connection.prepareCall(
          "DECLARE\n"
              + "  l_User_ID NUMBER :=?;\n"
              + "  l_ShortName_NM VARCHAR(32767);\n"
              + "  l_FullName VARCHAR(32767);\n"
              + "  l_Token VARCHAR2(32767);\n"
              + "BEGIN\n"
              + "  KER_User_PG.mp_SetUserID;\n"
              + "  SELECT\n"
              + "        usr.shortname_nm\n"
              + "      , usr.fullname\n"
              + "    INTO\n"
              + "        l_ShortName_NM"
              + "      , l_FullName\n"
              + "    FROM\n"
              + "        ker_receiver_tb usr\n"
              + "    WHERE\n"
              + "          (usr.receiver_id=l_User_ID)\n"
              + "    ;\n"
              + "  l_Token:=KER_User_PG.mf_CreateToken(SYSDATE+1/24);\n"
              + "  ?:=l_ShortName_NM;\n"
              + "  ?:=l_FullName;\n"
              + "  ?:=l_Token;\n"
              + "END;")) {
        statement.setBigDecimal(1, new BigDecimal(userId.getValue()));
        statement.registerOutParameter(2, Types.VARCHAR);
        statement.registerOutParameter(3, Types.VARCHAR);
        statement.registerOutParameter(4, Types.VARCHAR);
        statement.execute();
        return new ProvysUserData(
            userId,
            statement.getString(2),
            statement.getString(3),
            statement.getString(4));
      }
    } catch (SQLException e) {
      LOG.warn("Property retrieval from database failed (userId {}, user {}, db {}): {}",
          userId, provysDbUser, provysDbUrl, e);
      throw new InternalException("Property retrieval from database failed" + e.getErrorCode()
          + e.getMessage(), e);
    }
  }

  @Override
  public boolean equals(@Nullable Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    UserDataFactory that = (UserDataFactory) o;
    // datasource comparison is intentionally omitted
    return provysDbUrl.equals(that.provysDbUrl)
        && provysDbUser.equals(that.provysDbUser)
        && provysDbPwd.equals(that.provysDbPwd);
  }

  @Override
  public int hashCode() {
    int result = provysDbUrl.hashCode();
    result = 31 * result + provysDbUser.hashCode();
    result = 31 * result + provysDbPwd.hashCode();
    // datasource is intentionally omitted
    return result;
  }

  @Override
  public String toString() {
    return "UserDataFactory{"
        + "provysDbUrl='" + provysDbUrl + '\''
        + ", provysDbUser='" + provysDbUser + '\''
        // password and datasource are intentionally omitted
        + '}';
  }
}
