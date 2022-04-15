package com.auth.scp.payload.request;

import javax.validation.constraints.NotBlank;

//login request class
public class LoginRequest {
	
	//username and password can't be blank
	
	@NotBlank
  private String username;

	@NotBlank
	private String password;

	public String getUsername() {
		return username;
	}

	public void setUsername(String username) {
		this.username = username;
	}

	public String getPassword() {
		return password;
	}

	public void setPassword(String password) {
		this.password = password;
	}
}
