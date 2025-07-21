package org.security.jwt.springsecurity.model;

import lombok.Builder;
import lombok.Getter;
import lombok.Setter;

@Builder
public class AuthRequest {
  @Setter
  @Getter
  private String username;
  @Setter
  @Getter
  private String password;

  @Setter
  @Getter
  private String roles;
}
