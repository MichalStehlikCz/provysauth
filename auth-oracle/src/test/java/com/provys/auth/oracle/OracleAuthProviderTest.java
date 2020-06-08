package com.provys.auth.oracle;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.provys.auth.api.UserData;
import com.provys.auth.api.UserDataFactory;
import java.sql.Connection;
import java.sql.SQLException;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

class OracleAuthProviderTest {

  @Test
  void authenticateTest() throws SQLException {
    var user = "user";
    var pwd = "pwd";
    var dataSource = mock(DataSource.class);
    var userDataFactory = mock(UserDataFactory.class);
    var authProvider = new OracleAuthProvider("url", dataSource, 100,
        userDataFactory);
    var connection = mock(Connection.class);
    when(dataSource.getConnection(user, pwd)).thenReturn(connection);
    var userData = mock(UserData.class);
    when(userDataFactory.getUserData(connection)).thenReturn(userData);
    var result = authProvider.doAuthenticate(user, pwd);
    assertThat(result.getPrincipal()).isEqualTo(userData);
  }
}