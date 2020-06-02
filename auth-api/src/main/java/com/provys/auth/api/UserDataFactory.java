package com.provys.auth.api;

import com.provys.common.datatype.DtUid;
import com.provys.common.exception.InternalException;
import java.math.BigDecimal;
import java.sql.Connection;
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

  /**
   * Constructor creates user data factory that will read data about user from database. Does not
   * use provysdb for database access because provysdb depends on auth and not the other way around,
   * even though it means that database calls are not logged when using logging on DbConnection
   * level.
   *
   * @param provysDbUrl is jdbc thin url of provys database
   * @param provysDbUser is technical account, used to connect to database
   * @param provysDbPwd is password for technical account, used to connect to database
   */
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

  /**
   * Retrieve user data object from supplied connection.
   *
   * @param connection is connection user data should be read from
   * @return user data read from connection
   */
  public UserData getUserData(Connection connection) {
    try (var statement = connection.prepareCall(
        "DECLARE\n"
            + "  l_User_ID NUMBER;\n"
            + "  l_ShortName_NM VARCHAR(32767);\n"
            + "  l_FullName VARCHAR(32767);\n"
            + "  l_Token VARCHAR2(32767);\n"
            + "BEGIN\n"
            + "  l_User_ID:=KER_User_EP.mf_GetUserID;\n"
            + "  SELECT\n"
            + "        usr.shortname_nm\n"
            + "      , usr.fullname\n"
            + "    INTO\n"
            + "        l_ShortName_NM"
            + "      , l_FullName\n"
            + "    FROM\n"
            + "        kec_user_vw usr\n"
            + "    WHERE\n"
            + "          (usr.user_id=l_User_ID)\n"
            + "    ;\n"
            + "  l_Token:=KER_User_PG.mf_CreateToken(SYSDATE+1/24);\n"
            + "  ?:=l_User_ID;\n"
            + "  ?:=l_ShortName_NM;\n"
            + "  ?:=l_FullName;\n"
            + "  ?:=l_Token;\n"
            + "END;")) {
      statement.registerOutParameter(1, Types.NUMERIC);
      statement.registerOutParameter(2, Types.VARCHAR);
      statement.registerOutParameter(3, Types.VARCHAR);
      statement.registerOutParameter(4, Types.VARCHAR);
      statement.execute();
      return new ProvysUserData(
          DtUid.valueOf(statement.getBigDecimal(1)),
          statement.getString(2),
          statement.getString(3),
          statement.getString(4));
    } catch (SQLException e) {
      LOG.warn("Property retrieval from database failed (user {}, db {}): {}",
          provysDbUser, provysDbUrl, e);
      throw new InternalException("Property retrieval from database failed" + e.getErrorCode()
          + e.getMessage(), e);
    }
  }

  /**
   * Retrieve user data for specified user. Technical user must be able to impersonate this user in
   * order for function to work.
   *
   * @param userId is Id of user whose data we want to read
   * @return user data record for given user
   */
  public UserData getUserData(DtUid userId) {
    try (var connection = dataSource.getConnection(provysDbUser, provysDbPwd)) {
      try (var statement = connection.prepareCall(
          "DECLARE\n"
              + "  l_User_ID NUMBER :=?;\n"
              + "BEGIN\n"
              + "  KER_User_PG.mp_SetUserID(\n"
              + "        p_User_ID => l_User_ID\n"
              + "      , p_TestRights => FALSE\n"
              + "    );\n"
              + "END;")) {
        statement.setBigDecimal(1, new BigDecimal(userId.getValue()));
        statement.execute();
        return getUserData(connection);
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
