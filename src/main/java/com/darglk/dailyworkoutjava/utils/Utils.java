package com.darglk.dailyworkoutjava.utils;

import com.darglk.dailyworkoutjava.exception.ValidationException;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.validation.Errors;

public class Utils {

	private Utils() {}
	
	public static final String BEARER_TOKEN = "Bearer ";
	
	/**
	 * Method used to remove access and refresh tokens from token store.
	 * @param accessToken - access token to be removed.
	 * @param tokenStore - token store where access token is stored.
	 */
	public static void removeTokens(OAuth2AccessToken accessToken, TokenStore tokenStore) {
		OAuth2RefreshToken refreshToken = accessToken.getRefreshToken();
		if (refreshToken != null) {
			tokenStore.removeRefreshToken(refreshToken);
		}
		tokenStore.removeAccessToken(accessToken);
	}
	
	public static void sleepSeconds(long millis) {
		try {
			Thread.sleep(millis);
		} catch (InterruptedException e) {
			e.printStackTrace();
		}
	}

	public static void checkValidationErrors(Errors errors) {
		if (errors.hasErrors()) {
			throw new ValidationException(errors);
		}
	}
}
