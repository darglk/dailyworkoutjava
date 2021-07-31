package com.darglk.dailyworkoutjava.integrationtests;

import com.darglk.dailyworkoutjava.domain.user.entity.*;
import com.darglk.dailyworkoutjava.integrationtests.utils.OAuthClientParams;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.json.JacksonJsonParser;
import org.springframework.boot.json.JsonParseException;
import org.springframework.boot.json.JsonParser;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.io.UnsupportedEncodingException;
import java.util.*;
import java.util.stream.Collectors;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public abstract class BaseIntegrationTest {

	protected MockMvc mvc;
	
	protected ObjectMapper objectMapper;
	
	protected JsonParser jsonParser = new JacksonJsonParser();
	
	protected String nonHashedPassword = "aaZZa44@";
	
	protected String newNonHashedPassword = "bbXXb55#";
	
	protected String hashedPassword = "$2a$10$aIDEoNOSBEw.rLB1JZwm6eaxtoGd0Yv20GENwfp2YPhWlpqriz37S";
	
	protected MultiValueMap<String, String> oauthParams = new LinkedMultiValueMap<>();
	
	protected String accessTokenKey = "access_token";
	
	protected String refreshTokenKey = "refresh_token";
	
	public BaseIntegrationTest() {
		super();
	}
	
	public void setOauthParams(String grantType, String clientId, String username, String password) {
		oauthParams.add("grant_type", grantType);
		oauthParams.add("client_id", clientId);
		oauthParams.add("username", username);
		oauthParams.add("password", password);
	}

	@Autowired
	public final void setObjectMapper(ObjectMapper objectMapper) {
		this.objectMapper = objectMapper;
	}

	@Autowired
	public final void setMockMvc(MockMvc mockMvc) {
		this.mvc = mockMvc;
	}
	
	protected Map<String, Object> getJsonMap(MvcResult result) throws UnsupportedEncodingException {
		String responseString = result.getResponse().getContentAsString();
		return jsonParser.parseMap(responseString);
	}
	
	protected Map<String, Object> signIn(OAuthClientParams params, HttpStatus expectedHttpStatus) throws Exception {
		setOauthParams(params.getGrantType(), params.getClientId(), params.getUsername(), params.getPassword());
		MvcResult result = mvc.perform(post("/api/sign_in")
				.with(httpBasic(params.getClientId(), params.getClientDetailsPassword()))
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.params(oauthParams)
				.accept(MediaType.APPLICATION_JSON))
		.andExpect(status().is(expectedHttpStatus.value()))
		.andReturn();
		Map<String, Object> response = null;
		try {
			response = jsonParser.parseMap(result.getResponse().getContentAsString());
		} catch (JsonParseException e) {
			response = Collections.emptyMap();
		}
		oauthParams.clear();
		return response;
	}
	
	protected String getAccessToken(Map<String, Object> responseMap) throws Exception {
		return responseMap.get(accessTokenKey).toString();
	}
	
	protected Map<String, Object> refreshTokenRequest(OAuthClientParams params, HttpStatus expectedHttpStatus) throws Exception {
		setOauthParams(params.getGrantType(), params.getClientId(), params.getUsername(), params.getPassword());
		MultiValueMap<String, String> paramsMap = new LinkedMultiValueMap<>();
		paramsMap.add("grant_type", "refresh_token");
		paramsMap.add("client_id", params.getClientId());
		paramsMap.add("refresh_token", params.getRefreshToken());
		MvcResult result = mvc.perform(post("/api/sign_in")
				.with(httpBasic(params.getClientId(), params.getClientDetailsPassword()))
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.params(paramsMap)
				.accept(MediaType.APPLICATION_JSON))
		.andExpect(status().is(expectedHttpStatus.value()))
		.andReturn();
		paramsMap.clear();
		return jsonParser.parseMap(result.getResponse().getContentAsString());
	}
	
	protected void signOut(String accessToken, HttpStatus expectedHttpStatus) throws Exception {
		mvc.perform(delete("/api/sign_out")
				.header("Authorization", "Bearer " + accessToken)
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON))
		.andExpect(status().is(expectedHttpStatus.value()))
		.andReturn();
	}
	
	protected void aboutMeRequest(String accessToken, OAuthClientParams params, HttpStatus expectedHttpStatus) throws Exception {
		MultiValueMap<String, String> paramsMap = new LinkedMultiValueMap<>();
		paramsMap.add("client_id", params.getClientId());
		mvc.perform(get("/api/users/me")
				.with(httpBasic(params.getClientId(), params.getClientDetailsPassword()))
				.params(paramsMap)
				.header("Authorization", "Bearer " + accessToken)
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON))
		.andExpect(status().is(expectedHttpStatus.value()));
	}
	
	protected Authority createAuthority(AuthorityName authorityName) {
		Authority authority = new Authority();
		authority.setName(authorityName);
		return authority;
	}
	
	protected Role createRole(RoleName roleName) {
		Role role = new Role();
		role.setName(roleName);
		return role;
	}
	
	protected AppUser createEnabledUser(String emailAddress, Collection<Role> roles, Collection<Authority> authorities) {
		AppUser user = new AppUser();
		user.setEmail(emailAddress);
		user.setEnabled(true);
		user.setPassword(hashedPassword);
		//user.setLastAccountUpdateDate(Date.from(Instant.now()));
		user.getRoles().addAll(roles);
		user.getAuthorities().addAll(authorities);
		return user;
	}
	
	protected Map<String, Object> getResponseMapFromMvcResult(MvcResult mvcResult) throws JsonParseException, UnsupportedEncodingException {
		return jsonParser.parseMap(mvcResult.getResponse().getContentAsString());
	}
	
	protected Map<String, List<String>> extractValidationErrorMapFromResponse(MvcResult mvcResult) throws JsonParseException, UnsupportedEncodingException {
		Map<String, List<String>> validationErrors = new HashMap<>();
		((Map<?, ?>)getResponseMapFromMvcResult(mvcResult).get("errors")).entrySet().forEach(entry -> {
			validationErrors.compute(entry.getKey().toString(), (k, v) -> {
				if (v == null) {
					List<String> errorList = new ArrayList<>();
					errorList.addAll(((List<?>)entry.getValue()).stream().map(o -> o.toString()).collect(Collectors.toList()));
					return errorList;
				}
				v.add(entry.getValue().toString());
				return v;
			});
		});
		return validationErrors;
	}
	
	protected BaseClientDetails createBaseClientDetails(String clientId, String plainPassword, List<? extends GrantedAuthority> authorities, int accessTokenValidity, int refreshTokenValidity) {
		BaseClientDetails baseClientDetails = new BaseClientDetails();
		baseClientDetails.setClientId(clientId);
		baseClientDetails.setClientSecret(plainPassword);
		baseClientDetails.setScope(Arrays.asList("read", "write"));
		baseClientDetails.setResourceIds(Arrays.asList("oauth_server_api"));
		baseClientDetails.setAuthorizedGrantTypes(Arrays.asList("refresh_token", "password"));
		baseClientDetails.setRegisteredRedirectUri(Arrays.asList("http://localhost:8000").stream().collect(Collectors.toSet()));
		baseClientDetails.setAutoApproveScopes(Arrays.asList("true"));
		baseClientDetails.setAuthorities(authorities);
		baseClientDetails.setAccessTokenValiditySeconds(accessTokenValidity);
		baseClientDetails.setRefreshTokenValiditySeconds(refreshTokenValidity);
		
		return baseClientDetails;
	}
}
