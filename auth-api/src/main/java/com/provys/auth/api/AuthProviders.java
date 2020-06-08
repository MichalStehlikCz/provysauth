package com.provys.auth.api;

/**
 * Class provider translation of authentication provider to bean name. Only needed until
 * authentication is connected to ProvysAuth service.
 */
enum AuthProviders {

  ORACLE("oracleAuthProvider"),
  EXTUSER("extUserAuthProvider"),
  NONE("noneAuthProvider"),
  MOCK("mockAuthProvider");

  private final String beanName;

  AuthProviders(String beanName) {
    this.beanName = beanName;
  }

  /**
   * Value of field beanName.
   *
   * @return value of field beanName
   */
  public String getBeanName() {
    return beanName;
  }

  @Override
  public String toString() {
    return "AuthProviders{"
        + "beanName='" + beanName + '\''
        + ", " + super.toString() + '}';
  }
}
