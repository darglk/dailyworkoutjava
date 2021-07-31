package com.darglk.dailyworkoutjava.integrationtests;

import com.darglk.dailyworkoutjava.DailyworkoutjavaApplication;

import com.darglk.dailyworkoutjava.domain.user.entity.*;
import com.darglk.dailyworkoutjava.domain.user.repository.AuthorityRepository;
import com.darglk.dailyworkoutjava.domain.user.repository.PasswordTokenRepository;
import com.darglk.dailyworkoutjava.domain.user.repository.RoleRepository;
import com.darglk.dailyworkoutjava.domain.user.repository.UserRepository;
import com.darglk.dailyworkoutjava.domain.user.request.ForgotPasswordRequestModel;
import com.darglk.dailyworkoutjava.domain.user.request.admin.PasswordRequestModel;
import com.darglk.dailyworkoutjava.integrationtests.utils.OAuthClientParams;
import com.darglk.dailyworkoutjava.utils.ResponseMessages;
import com.darglk.dailyworkoutjava.utils.ValidationErrorMessages;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.time.Instant;
import java.time.Period;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest(
	webEnvironment = WebEnvironment.DEFINED_PORT,
	classes = DailyworkoutjavaApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(locations = "classpath:application-test.properties")
@DirtiesContext(classMode = ClassMode.AFTER_CLASS)
public class ForgotPasswordIntegrationTest extends BaseIntegrationTest {

	private UserRepository userRepository;

	private AuthorityRepository authorityRepository;

	private RoleRepository roleRepository;

	private PasswordTokenRepository passwordTokenRepository;
	
	private AppUser standardUser;
	
	private ForgotPasswordRequestModel forgotPasswordResetModel;
	
	private PasswordRequestModel resetPasswordModel;
	
	private PasswordResetToken passwordToken;
	
	private JdbcClientDetailsService clientDetailsService;
	
	private ClientDetails clientDetails;
	
	private String clientId = "oauth_client_id";

	private OAuthClientParams params;
	
	@Autowired
	public ForgotPasswordIntegrationTest(UserRepository userRepository, AuthorityRepository authorityRepository,
			RoleRepository roleRepository, PasswordTokenRepository passwordTokenRepository, JdbcClientDetailsService clientDetailsService) {
		this.userRepository = userRepository;
		this.authorityRepository = authorityRepository;
		this.roleRepository = roleRepository;
		this.passwordTokenRepository = passwordTokenRepository;
		this.clientDetailsService = clientDetailsService;
	}

	@BeforeEach
	public void setUp() {
		Authority authority = createAuthority(AuthorityName.READ_AUTHORITY);
		Authority createAuthority = createAuthority(AuthorityName.CREATE_AUTHORITY);
		
		Role role = createRole(RoleName.ROLE_USER);
		Role admin = createRole(RoleName.ROLE_ADMIN);
		
		roleRepository.save(role);
		roleRepository.save(admin);
		authorityRepository.save(authority);
		authorityRepository.save(createAuthority);
		
		standardUser = createEnabledUser("test@test.com", Arrays.asList(role), Arrays.asList(authority));
		userRepository.save(standardUser);
		
		forgotPasswordResetModel = new ForgotPasswordRequestModel();
		forgotPasswordResetModel.setEmail(standardUser.getEmail());
		
		resetPasswordModel = new PasswordRequestModel();
		resetPasswordModel.setPassword(newNonHashedPassword);
		resetPasswordModel.setPasswordConfirmation(newNonHashedPassword);
		
		passwordToken = new PasswordResetToken();
		passwordToken.setExpiryDate(Date.from(Instant.now().plus(Period.ofDays(1))));
		passwordToken.setToken(UUID.randomUUID().toString());
		passwordToken.setUser(standardUser);
		
		int accessTokenValidity = 30;
		int refreshTokenValidity = 60;
		clientDetails = createBaseClientDetails(clientId , hashedPassword, standardUser.getAllAuthorities(), accessTokenValidity , refreshTokenValidity);
		clientDetailsService.addClientDetails(clientDetails);
		
		params = new OAuthClientParams();
		params.setClientDetailsPassword(nonHashedPassword);
		params.setClientId(clientId);
		params.setGrantType("password");
		params.setPassword(nonHashedPassword);
		params.setUsername(standardUser.getEmail());
	}
	
	@AfterEach
	public void tearDown() {
		passwordTokenRepository.deleteAll();
		roleRepository.deleteAll();
		authorityRepository.deleteAll();
		userRepository.deleteAll();
		clientDetailsService.listClientDetails().forEach(client -> {
			clientDetailsService.removeClientDetails(client.getClientId());
		});
	}
	
	@Test
	public void testChangeForgottenPasswordShouldSucceedWhenAllDataIsCorrect() throws Exception {
		Map<String, Object> oauthTokenResponse = signIn(params, HttpStatus.OK);
		MvcResult mvcResult = sendForgotPasswordRequest(forgotPasswordResetModel, params, HttpStatus.OK);
		Map<String, Object> jsonMap = jsonParser.parseMap(mvcResult.getResponse().getContentAsString());
		String msg = (String) jsonMap.get("message");
		
		assertEquals(msg, ResponseMessages.PASSWORD_TOKEN_CREATED_MESSAGE);
		
		String accessToken = oauthTokenResponse.get(accessTokenKey).toString();
		signOut(accessToken, HttpStatus.UNAUTHORIZED);
		
		String refreshToken = oauthTokenResponse.get(refreshTokenKey).toString();
		params.setRefreshToken(refreshToken);
		refreshTokenRequest(params, HttpStatus.BAD_REQUEST);
		
		AppUser user = userRepository.findAppUserByUserDataEmail(forgotPasswordResetModel.getEmail());
		PasswordResetToken passwordToken = passwordTokenRepository.findByUser(user);
		
		assertNotNull(passwordToken);
		
		oauthTokenResponse = signIn(params, HttpStatus.OK);
		
		PasswordRequestModel newPassword = new PasswordRequestModel(newNonHashedPassword, newNonHashedPassword);
		mvcResult = sendForgotPasswordRequest(newPassword, params, user.getId(), passwordToken.getToken(), HttpStatus.OK);
		jsonMap = getJsonMap(mvcResult);
		msg = (String) jsonMap.get("message");
		
		accessToken = oauthTokenResponse.get(accessTokenKey).toString();
		signOut(accessToken, HttpStatus.UNAUTHORIZED);
		
		refreshToken = oauthTokenResponse.get(refreshTokenKey).toString();
		params.setRefreshToken(refreshToken);
		refreshTokenRequest(params, HttpStatus.BAD_REQUEST);
		
		assertEquals(msg, ResponseMessages.PASSWORD_HAS_BEEN_CHANGED_MESSAGE);
		
		signIn(params, HttpStatus.UNAUTHORIZED);
		
		params.setPassword(newNonHashedPassword);
		oauthTokenResponse = signIn(params, HttpStatus.OK);
		accessToken = oauthTokenResponse.get(accessTokenKey).toString();
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testChangeForgottenPasswordShouldFailWhenTokenIsExpired() throws Exception {
		MvcResult mvcResult = sendForgotPasswordRequest(forgotPasswordResetModel, params, HttpStatus.OK);
		Map<String, Object> jsonMap = getJsonMap(mvcResult);
		String msg = (String) jsonMap.get("message");
		
		assertEquals(msg, ResponseMessages.PASSWORD_TOKEN_CREATED_MESSAGE);
		
		AppUser user = userRepository.findAppUserByUserDataEmail(forgotPasswordResetModel.getEmail());
		PasswordResetToken passwordToken = passwordTokenRepository.findByUser(user);
		passwordToken.setExpiryDate(Date.from(Instant.now().minus(Period.ofDays(1))));
		passwordTokenRepository.save(passwordToken);
		
		PasswordRequestModel newPassword = new PasswordRequestModel(newNonHashedPassword, newNonHashedPassword);
		mvcResult = sendForgotPasswordRequest(newPassword, params, user.getId(), passwordToken.getToken(), HttpStatus.BAD_REQUEST);
		jsonMap = getJsonMap(mvcResult);
		msg = (String) jsonMap.get("message");
		assertEquals(msg, ValidationErrorMessages.PASSWORD_RESET_TOKEN_EXPIRED_MESSAGE);
	}
	
	@Test
	public void testForgotPasswordRequestFailsWhenEmailDoesNotExist() throws Exception {
		forgotPasswordResetModel.setEmail("doesnt@exist.com");
		MvcResult mvcResult = sendForgotPasswordRequest(forgotPasswordResetModel, params, HttpStatus.NOT_FOUND);
		Map<String, Object> jsonMap = getJsonMap(mvcResult);
		String msg = (String) jsonMap.get("message");
		assertEquals(msg, ValidationErrorMessages.USER_NOT_FOUND_MESSAGE);
	}
	
	@Test
	public void testForgotPasswordRequestFailsWhenEmailIsInvalid() throws Exception {
		forgotPasswordResetModel.setEmail("invalid");
		MvcResult mvcResult = sendForgotPasswordRequest(forgotPasswordResetModel, params, HttpStatus.BAD_REQUEST);

		Map<String, List<String>> errorMessages = extractValidationErrorMapFromResponse(mvcResult);
		int expectedErrorMessagesLength = 1;
		assertEquals(errorMessages.size(), expectedErrorMessagesLength);
		assertTrue(errorMessages.get("email").contains(ValidationErrorMessages.EMAIL_INVALID_MESSAGE));
	}
	
	@Test
	public void testForgotPasswordRequestFailsWhenEmailIsNull() throws Exception {
		forgotPasswordResetModel.setEmail(null);
		MvcResult mvcResult = sendForgotPasswordRequest(forgotPasswordResetModel, params, HttpStatus.BAD_REQUEST);
		
		Map<String, List<String>> errorMessages = extractValidationErrorMapFromResponse(mvcResult);
		int expectedEmailErrorMessagesLength = 1;
		int expectedErrorMessagesLength = 1;
		List<String> emailValidationErrors = errorMessages.get("email");

		assertEquals(errorMessages.size(), expectedErrorMessagesLength);
		assertEquals(emailValidationErrors.size(), expectedEmailErrorMessagesLength);
		assertTrue(emailValidationErrors.contains(ValidationErrorMessages.EMAIL_NOT_BLANK_MESSAGE));
	}
	
	@Test
	public void testChangeForgottenPasswordShouldFailWhenPasswordIsInvalid() throws Exception {
		passwordTokenRepository.save(passwordToken);
		
		PasswordRequestModel newPassword = new PasswordRequestModel("invalid", newNonHashedPassword);
		MvcResult mvcResult = sendForgotPasswordRequest(newPassword, params, standardUser.getId(), passwordToken.getToken(), HttpStatus.BAD_REQUEST);
		Map<String, List<String>> errorMessages = extractValidationErrorMapFromResponse(mvcResult);
		int expectedErrorMessagesLength = 2;
		assertEquals(errorMessages.keySet().size(), expectedErrorMessagesLength);
		assertTrue(errorMessages.get("password").contains(ValidationErrorMessages.INVALID_PASSWORD_MESSAGE));
		assertTrue(errorMessages.get("other").contains(ValidationErrorMessages.PASSWORDS_NOT_EQUAL_MESSAGE));
	}
	
	@Test
	public void testChangeForgottenPasswordShouldFailWhenPasswordConfirmationIsInvalid() throws Exception {
		passwordTokenRepository.save(passwordToken);
		
		PasswordRequestModel newPassword = new PasswordRequestModel(newNonHashedPassword, "invalid");
		MvcResult mvcResult = sendForgotPasswordRequest(newPassword, params, standardUser.getId(), passwordToken.getToken(), HttpStatus.BAD_REQUEST);
		Map<String, List<String>> errorMessages = extractValidationErrorMapFromResponse(mvcResult);

		int expectedErrorMessagesLength = 2;
		assertEquals(errorMessages.size(), expectedErrorMessagesLength);
		assertTrue(errorMessages.get("passwordConfirmation").contains(ValidationErrorMessages.INVALID_PASSWORD_CONFIRMATION_MESSAGE));
		assertTrue(errorMessages.get("other").contains(ValidationErrorMessages.PASSWORDS_NOT_EQUAL_MESSAGE));
	}
	
	@Test
	public void testChangeForgottenPasswordShouldFailWhenPasswordsAreNull() throws Exception {
		passwordTokenRepository.save(passwordToken);
		
		PasswordRequestModel newPassword = new PasswordRequestModel(null, null);
		MvcResult mvcResult = sendForgotPasswordRequest(newPassword, params, standardUser.getId(), passwordToken.getToken(), HttpStatus.BAD_REQUEST);
		Map<String, List<String>> errorMessages = extractValidationErrorMapFromResponse(mvcResult);

		int expectedErrorMessagesLength = 3;
		assertEquals(errorMessages.size(), expectedErrorMessagesLength);
		assertTrue(errorMessages.get("other").contains(ValidationErrorMessages.PASSWORDS_NOT_EQUAL_MESSAGE));
		assertTrue(errorMessages.get("passwordConfirmation").contains(ValidationErrorMessages.PASSWORD_CONFIRMATION_NOT_EMPTY_MESSAGE));
		assertTrue(errorMessages.get("password").contains(ValidationErrorMessages.PASSWORD_NOT_EMPTY_MESSAGE));
	}
	
	@Test
	public void testChangeForgottenPasswordShouldFailWhenUserIdIsInvalid() throws Exception {
		passwordTokenRepository.save(passwordToken);
		String invalidUserId = "dup";
		PasswordRequestModel newPassword = new PasswordRequestModel(newNonHashedPassword, newNonHashedPassword);
		MvcResult mvcResult = sendForgotPasswordRequest(newPassword, params, invalidUserId, passwordToken.getToken(), HttpStatus.NOT_FOUND);
		Map<String, Object> jsonMap = getJsonMap(mvcResult);
		String msg = (String) jsonMap.get("message");
		assertEquals(msg, ValidationErrorMessages.INVALID_PASSWORD_RESET_TOKEN_MESSAGE);
	}
	
	@Test
	public void testChangeForgottenPasswordShouldFailWhenTokenIsInvalid() throws Exception {
		passwordTokenRepository.save(passwordToken);
		String invalidResetToken = "ABCDEF";
		PasswordRequestModel newPassword = new PasswordRequestModel(newNonHashedPassword, newNonHashedPassword);
		MvcResult mvcResult = sendForgotPasswordRequest(newPassword, params, standardUser.getId(), invalidResetToken, HttpStatus.NOT_FOUND);
		Map<String, Object> jsonMap = getJsonMap(mvcResult);
		String msg = (String) jsonMap.get("message");
		assertEquals(msg, ValidationErrorMessages.INVALID_PASSWORD_RESET_TOKEN_MESSAGE);
	}
	
	private MvcResult sendForgotPasswordRequest(ForgotPasswordRequestModel body, OAuthClientParams params, HttpStatus expectedHttpStatus) throws Exception {
		String requestBodyString = objectMapper.writeValueAsString(body);
		MultiValueMap<String, String> paramsMap = new LinkedMultiValueMap<>();
		paramsMap.add("client_id", params.getClientId());
		return mvc.perform(post("/api/users/forgot_password")
				.with(httpBasic(params.getClientId(), params.getClientDetailsPassword()))
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON)
				.params(paramsMap)
				.content(requestBodyString))
		.andExpect(status().is(expectedHttpStatus.value()))
		.andReturn();
	}
	
	private MvcResult sendForgotPasswordRequest(PasswordRequestModel body, OAuthClientParams params, String userId, String token, HttpStatus expectedHttpStatus) throws Exception {
		String requestBodyString = objectMapper.writeValueAsString(body);
		MultiValueMap<String, String> paramsMap = new LinkedMultiValueMap<>();
		paramsMap.add("client_id", params.getClientId());
		return mvc.perform(post("/api/users/reset_password?token=" + token + "&userId=" + userId)
				.with(httpBasic(params.getClientId(), params.getClientDetailsPassword()))
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON)
				.params(paramsMap)
				.content(requestBodyString))
		.andExpect(status().is(expectedHttpStatus.value()))
		.andReturn();
	}
}
