package com.darglk.dailyworkoutjava.domain.user.controller;

import com.darglk.dailyworkoutjava.utils.Utils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

/**
 * Controller class for signing out.
 * @author Dariusz Kulig
 *
 */
@RestController
public class LogoutController {

	/**
	 * tokenStore - used for caching access tokens.
	 */
	@Autowired
	private TokenStore tokenStore;

	/**
	 * Endpoint where all signed in users can revoke access and refresh tokens.
	 * @param request - http servlet request instance containing headers with tokens.
	 * @return Empty response when all tokens will be valid. Otherwise 400 error will be sent.
	 * @throws ServletException 
	 */
	@RequestMapping(method = RequestMethod.DELETE, value = "/api/sign_out")
	public ResponseEntity<?> logout(HttpServletRequest request) throws ServletException {
		String authorization = request.getHeader("Authorization");
		if (authorization != null && authorization.contains("Bearer")) {
			String tokenId = authorization.substring("Bearer".length() + 1);
			OAuth2AccessToken oauthAccessToken = tokenStore.readAccessToken(tokenId);
			if (oauthAccessToken != null) {
				Utils.removeTokens(oauthAccessToken, tokenStore);
			}
			return ResponseEntity.noContent().build();
		}
		SecurityContextHolder.clearContext();
		request.logout();
		return ResponseEntity.badRequest().contentType(MediaType.APPLICATION_JSON).build();
	}
}