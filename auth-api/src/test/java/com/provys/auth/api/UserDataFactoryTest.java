package com.provys.auth.api;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.provys.common.crypt.DtEncryptedString;
import com.provys.common.datatype.DtUid;
import java.math.BigDecimal;
import java.sql.CallableStatement;
import java.sql.Connection;
import java.sql.SQLException;
import org.junit.jupiter.api.Test;


class UserDataFactoryTest {

  @Test
  void getUserDataConnectionTest() throws SQLException {
    var factory = new UserDataFactory(
        "localhost:1000:PVYS", "test", "test");
    var connection = mock(Connection.class);
    var preparedCall = mock(CallableStatement.class);
    when(connection.prepareCall(anyString())).thenReturn(preparedCall);
    var uid = new BigDecimal("5214489678945156");
    when(preparedCall.getBigDecimal(1)).thenReturn(uid);
    var shortNameNm = "TESTUSER";
    when(preparedCall.getString(2)).thenReturn(shortNameNm);
    var fullName = "User Userovic";
    when(preparedCall.getString(3)).thenReturn(fullName);
    var dbToken = DtEncryptedString.valueOf("KJNjkdDOICHJoiijoi");
    when(preparedCall.getString(4)).thenReturn(dbToken.getIisValue());
    var userData = factory.getUserData(connection);
    assertThat(userData.getUserId()).isEqualTo(DtUid.valueOf(uid));
    assertThat(userData.getShortNameNm()).isEqualTo(shortNameNm);
    assertThat(userData.getFullName()).isEqualTo(fullName);
    assertThat(userData.getDbToken()).isEqualTo(dbToken);
  }
}