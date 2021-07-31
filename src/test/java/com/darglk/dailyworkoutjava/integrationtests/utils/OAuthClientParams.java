package com.darglk.dailyworkoutjava.integrationtests.utils;

import lombok.Data;

@Data
public class OAuthClientParams {

	private String grantType;
	private String clientId;
	private String username;
	private String password;
	private String clientDetailsPassword;
	private String refreshToken;
}
