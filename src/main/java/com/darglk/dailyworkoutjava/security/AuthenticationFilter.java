package com.darglk.dailyworkoutjava.security;

import com.darglk.dailyworkoutjava.domain.user.entity.AppUser;
import com.darglk.dailyworkoutjava.domain.user.repository.UserRepository;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpointAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.time.Instant;
import java.util.Date;

public class AuthenticationFilter extends TokenEndpointAuthenticationFilter {

	private UserRepository userRepository;
	
	public AuthenticationFilter(AuthenticationManager authenticationManager,
			OAuth2RequestFactory oAuth2RequestFactory, UserRepository userRepository) {
		super(authenticationManager, oAuth2RequestFactory);
		this.userRepository = userRepository;
	}
	
	@Override
	protected void onSuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response,
			Authentication authResult) throws IOException {
		AppUser signedInUser = userRepository.findAppUserByUserDataEmail(authResult.getName());
		signedInUser.setLastSignInDate(Date.from(Instant.now()));
		signedInUser.setLastSignInIp(request.getRemoteAddr());
		userRepository.save(signedInUser);
	}
}
