package com.provys.auth.extuser;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import com.provys.auth.api.UserDataFactory;
import com.provys.auth.api.UserData;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.SQLException;
import javax.sql.DataSource;
import org.junit.jupiter.api.Test;

class ExtUserAuthProviderTest {

  @Test
  void authenticateTest() throws SQLException {
    var user = "user";
    var pwd = "pwd";
    var dataSource = mock(DataSource.class);
    var userDataFactory = mock(UserDataFactory.class);
    var authProvider = new ExtUserAuthProvider("url", user, pwd, dataSource,
        100, userDataFactory);
    var connection = mock(Connection.class);
    when(dataSource.getConnection(user, pwd)).thenReturn(connection);
    var preparedCall = mock(CallableStatement.class);
    when(connection.prepareCall(anyString())).thenReturn(preparedCall);
    var userData = mock(UserData.class);
    when(userDataFactory.getUserData(connection)).thenReturn(userData);
    var result = authProvider.doAuthenticate("stehlik", "atlanta");
    assertThat(result.getPrincipal()).isEqualTo(userData);
    verify(preparedCall).setString(1, "STEHLIK");
    verify(preparedCall).setString(2, "mg0xgiwpOtkE9v4gJPKgjTzj6Gvk/zd6yHksHxY7/4o"
        + "D0XtTUNEDSJakmH6vTSFIZK0C0b80DIcjKuu+ep887Q==");
    verify(preparedCall).execute();
  }
}