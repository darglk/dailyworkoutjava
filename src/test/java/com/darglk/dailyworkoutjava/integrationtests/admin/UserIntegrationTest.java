package com.darglk.dailyworkoutjava.integrationtests.admin;

import com.darglk.dailyworkoutjava.DailyworkoutjavaApplication;
import com.darglk.dailyworkoutjava.domain.user.entity.*;
import com.darglk.dailyworkoutjava.domain.user.entity.embedded.UserData;
import com.darglk.dailyworkoutjava.domain.user.repository.AuthorityRepository;
import com.darglk.dailyworkoutjava.domain.user.repository.RoleRepository;
import com.darglk.dailyworkoutjava.domain.user.repository.UserRepository;
import com.darglk.dailyworkoutjava.domain.user.request.UserDataRequestModel;
import com.darglk.dailyworkoutjava.domain.user.request.UserLoginRequestModel;
import com.darglk.dailyworkoutjava.domain.user.request.admin.PasswordRequestModel;
import com.darglk.dailyworkoutjava.domain.user.request.admin.UserDataExtendedModel;
import com.darglk.dailyworkoutjava.domain.user.request.admin.UserModelRequest;
import com.darglk.dailyworkoutjava.integrationtests.BaseIntegrationTest;
import com.darglk.dailyworkoutjava.integrationtests.utils.OAuthClientParams;
import com.darglk.dailyworkoutjava.utils.ValidationErrorMessages;
import com.github.javafaker.Faker;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
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

import java.io.UnsupportedEncodingException;
import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest(webEnvironment = WebEnvironment.DEFINED_PORT, classes = DailyworkoutjavaApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(locations = "classpath:application-test.properties")
@DirtiesContext(classMode = ClassMode.AFTER_CLASS)
public class UserIntegrationTest extends BaseIntegrationTest {

	private final UserRepository userRepository;

	private final AuthorityRepository authorityRepository;

	private final RoleRepository roleRepository;

	private AppUser adminUser;
	
	private AppUser standardUser;

	private final UserLoginRequestModel credentials = new UserLoginRequestModel();
	
	private final UserModelRequest userRequest= new UserModelRequest();
	
	@Value("${config.pagination.default_page_offset}")
	private int PER_PAGE;
	
	private final Faker faker = new Faker();

	private final UserDataExtendedModel userDataRequest = new UserDataExtendedModel();
	
	private final PasswordRequestModel passwordRequest = new PasswordRequestModel();

	private String clientId = "oauth_client_id";

	private OAuthClientParams params;
	
	private final JdbcClientDetailsService clientDetailsService;
	
	@Autowired
	public UserIntegrationTest(UserRepository userRepository, AuthorityRepository authorityRepository,
                               RoleRepository roleRepository, JdbcClientDetailsService clientDetailsService) {
		this.userRepository = userRepository;
		this.authorityRepository = authorityRepository;
		this.roleRepository = roleRepository;
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
		standardUser.setLastPasswordResetDate(Date.from(Instant.now()));
		userRepository.save(standardUser);
		
		adminUser = createEnabledUser("admin@test.com", Arrays.asList(role, admin), Arrays.asList(authority, createAuthority));		
		adminUser.setLastPasswordResetDate(Date.from(Instant.now()));
		userRepository.save(adminUser);
		
		credentials.setEmail(adminUser.getEmail());
		credentials.setPassword(nonHashedPassword);

		UserDataRequestModel userData = new UserDataRequestModel();
		userData.setEmail("test1@test.com");

		userRequest.setUserData(userData);
		PasswordRequestModel passwords = new PasswordRequestModel(nonHashedPassword, nonHashedPassword);
		userRequest.setPasswords(passwords);
		userRequest.setEnabled(true);
		userRequest.setAuthorityIds(Stream.of(authority, createAuthority).map(Authority::getId).collect(Collectors.toSet()));
		userRequest.setRoleIds(Stream.of(role, admin).map(Role::getId).collect(Collectors.toSet()));

		userDataRequest.setAuthorityIds(userRequest.getAuthorityIds());
		userDataRequest.setRoleIds(userRequest.getRoleIds());
		userDataRequest.setEmail(userRequest.getUserData().getEmail());
		userDataRequest.setEnabled(true);

		passwordRequest.setPassword(newNonHashedPassword);
		passwordRequest.setPasswordConfirmation(newNonHashedPassword);
		
		int accessTokenValidity = 30;
		int refreshTokenValidity = 60;
		ClientDetails clientDetails = createBaseClientDetails(clientId, hashedPassword, standardUser.getAllAuthorities(), accessTokenValidity, refreshTokenValidity);
		clientDetailsService.addClientDetails(clientDetails);
		
		params = new OAuthClientParams();
		params.setClientDetailsPassword(nonHashedPassword);
		params.setClientId(clientId);
		params.setGrantType("password");
		params.setPassword(nonHashedPassword);
		params.setUsername(adminUser.getEmail());
	}
	
	@AfterEach
	public void tearDown() {
		userRepository.deleteAll();
		authorityRepository.deleteAll();
		authorityRepository.deleteAll();
		roleRepository.deleteAll();
		clientDetailsService.listClientDetails().forEach(client -> {
			clientDetailsService.removeClientDetails(client.getClientId());
		});
	}
	
	@Test
	public void testCreateNewUserShouldSucceed() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		MvcResult result = createAccount(userRequest, params, accessToken, HttpStatus.OK);
		Map<String, Object> responseMap = getJsonMap(result);
		checkPresenceOfFieldsInResponse(responseMap);
		AppUser found = userRepository.findById(responseMap.get("userId").toString()).get();
		compareResponseDataToAppUser(responseMap, found);
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testCreateNewUserWithExistingEmailShouldFail() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		UserDataRequestModel userDataReq = new UserDataRequestModel();
		userDataReq.setEmail(standardUser.getEmail());
		userRequest.setUserData(userDataReq);
		MvcResult result = createAccount(userRequest, params, accessToken, HttpStatus.BAD_REQUEST);
		Map<String, Object> responseMap = getJsonMap(result);

		assertEquals(ValidationErrorMessages.USERNAME_EXISTS_MESSAGE, responseMap.get("message"));
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testCreateNewUserWithInvalidEmailShouldFail() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		UserDataRequestModel userDataReq = new UserDataRequestModel();
		userDataReq.setEmail("invalid");
		userRequest.setUserData(userDataReq);
		MvcResult result = createAccount(userRequest, params, accessToken, HttpStatus.BAD_REQUEST);

		Map<String, List<String>> errorMessages = extractValidationErrorMapFromResponse(result);
		assertTrue(errorMessages.get("email").contains(ValidationErrorMessages.EMAIL_INVALID_MESSAGE));
		int expectedErrorsSize = 1;
		assertEquals(errorMessages.size(), expectedErrorsSize);
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testCreateNewUserWithNullEmailShouldFail() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		UserDataRequestModel userDataReq = new UserDataRequestModel();
		userDataReq.setEmail(null);
		userRequest.setUserData(userDataReq);
		MvcResult result = createAccount(userRequest, params, accessToken, HttpStatus.BAD_REQUEST);

		Map<String, List<String>> errorMessages = extractValidationErrorMapFromResponse(result);
		int expectedErrorsSize = 1;
		assertTrue(errorMessages.get("email").contains(ValidationErrorMessages.EMAIL_NOT_BLANK_MESSAGE));
		assertEquals(errorMessages.size(), expectedErrorsSize);
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testCreateNewUserWithNullUserDataShouldFail() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		userRequest.setUserData(null);
		MvcResult result = createAccount(userRequest, params, accessToken, HttpStatus.BAD_REQUEST);

		Map<String, List<String>> errorMessages = extractValidationErrorMapFromResponse(result);
		int expectedErrorsSize = 1;
		assertTrue(errorMessages.get("userData").contains(ValidationErrorMessages.USER_DATA_ATTRIBUTES_NOT_NULL_MESSAGE));
		assertEquals(errorMessages.size(), expectedErrorsSize);
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testCreateNewUserWithInvalidPasswordShouldFail() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		userRequest.getPasswords().setPassword("invalid");
		MvcResult result = createAccount(userRequest, params, accessToken, HttpStatus.BAD_REQUEST);

		Map<String, List<String>> errorMessages = extractValidationErrorMapFromResponse(result);
		int expectedErrorsSize = 2;
		assertTrue(errorMessages.get("password").contains(ValidationErrorMessages.INVALID_PASSWORD_MESSAGE));
		assertTrue(errorMessages.get("passwords").contains(ValidationErrorMessages.PASSWORDS_NOT_EQUAL_MESSAGE));
		assertEquals(errorMessages.size(), expectedErrorsSize);
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testCreateNewUserWithNullPasswordShouldFail() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		userRequest.getPasswords().setPassword(null);
		MvcResult result = createAccount(userRequest, params, accessToken, HttpStatus.BAD_REQUEST);

		Map<String, List<String>> errorMessages = extractValidationErrorMapFromResponse(result);
		int expectedErrorsSize = 2;
		assertTrue(errorMessages.get("password").contains(ValidationErrorMessages.PASSWORD_NOT_EMPTY_MESSAGE));
		assertTrue(errorMessages.get("passwords").contains(ValidationErrorMessages.PASSWORDS_NOT_EQUAL_MESSAGE));
		assertEquals(errorMessages.size(), expectedErrorsSize);
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}

	@Test
	public void testCreateNewUserWithInvalidPasswordConrimationShouldFail() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		userRequest.getPasswords().setPasswordConfirmation("invalid");
		MvcResult result = createAccount(userRequest, params, accessToken, HttpStatus.BAD_REQUEST);

		Map<String, List<String>> errorMessages = extractValidationErrorMapFromResponse(result);
		int expectedErrorsSize = 2;
		assertTrue(errorMessages.get("passwordConfirmation").contains(ValidationErrorMessages.INVALID_PASSWORD_CONFIRMATION_MESSAGE));
		assertTrue(errorMessages.get("passwords").contains(ValidationErrorMessages.PASSWORDS_NOT_EQUAL_MESSAGE));
		assertEquals(errorMessages.size(), expectedErrorsSize);
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testCreateNewUserWithNullPasswordConfirmationShouldFail() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		userRequest.getPasswords().setPasswordConfirmation(null);
		MvcResult result = createAccount(userRequest, params, accessToken, HttpStatus.BAD_REQUEST);

		Map<String, List<String>> errorMessages = extractValidationErrorMapFromResponse(result);
		int expectedErrorsSize = 2;
		assertTrue(errorMessages.get("passwordConfirmation").contains(ValidationErrorMessages.PASSWORD_CONFIRMATION_NOT_EMPTY_MESSAGE));
		assertTrue(errorMessages.get("passwords").contains(ValidationErrorMessages.PASSWORDS_NOT_EQUAL_MESSAGE));
		assertEquals(errorMessages.size(), expectedErrorsSize);
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}

	@Test
	public void testCreateNewUserWithNullEnabledFieldShouldFail() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		userRequest.setEnabled(null);
		MvcResult result = createAccount(userRequest, params, accessToken, HttpStatus.BAD_REQUEST);

		Map<String, List<String>> errorMessages = extractValidationErrorMapFromResponse(result);
		int expectedErrorsSize = 1;
		assertTrue(errorMessages.get("enabled").contains(ValidationErrorMessages.USER_ENABLED_NOT_EMPTY_MESSAGE));
		assertEquals(errorMessages.size(), expectedErrorsSize);
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}

	@Test
	public void testCreateNewUserWithEmptyAuthoritiesAndRolesShouldSucceed() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		userRequest.setAuthorityIds(Collections.emptySet());
		userRequest.setRoleIds(Collections.emptySet());
		MvcResult result = createAccount(userRequest, params, accessToken, HttpStatus.OK);
		Map<String, Object> responseMap = jsonParser.parseMap(result.getResponse().getContentAsString());
		AppUser found = userRepository.findById(responseMap.get("userId").toString()).get();
		assertTrue(found.getAuthorities().isEmpty());
		assertTrue(found.getRoles().isEmpty());
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}

	/*
 TODO: rewrite tests with pagination
	@Test
	public void testPaginationOfUsersWithoutSearchParams() throws Exception {
		int usersNum = 20;
		int perPageRequestParam = 7;
		List<AppUser> users = createAppUsers(usersNum, Optional.empty());
		users.add(0, adminUser);
		users.add(0, standardUser);
		Optional<String> emptySearchParams = Optional.empty();
		testPaginationOfUsers(emptySearchParams, params, emptySearchParams, Optional.empty(), users);
		testPaginationOfUsers(emptySearchParams, params, emptySearchParams, Optional.of(perPageRequestParam), users);
		testPaginationOfUsers(Optional.of(""), params, Optional.of(""), Optional.empty(), users);
	}

	@Test
	public void testPaginationOfUsersWithSearchByEmail() throws Exception {
		int usersNum = 10;
		String testDomainName = "testing.com";
		String otherDomainName = "other.com";
		String emailQueryParam = "email";
		List<AppUser> usersFromTestDomain = createAppUsers(usersNum, Optional.of(testDomainName));

		createAppUsers(usersNum, Optional.of(otherDomainName));

		testPaginationOfUsers(Optional.of(testDomainName), params, Optional.of(emailQueryParam), Optional.empty(), usersFromTestDomain);
		testPaginationOfUsers(Optional.of(testDomainName), params, Optional.empty(), Optional.empty(), usersFromTestDomain);
		testPaginationOfUsers(Optional.of(testDomainName), params, Optional.of(""), Optional.of(6), usersFromTestDomain);
	}
*/

	@Test
	public void testFetchExistingUserById() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		MvcResult result = fetchUser(standardUser.getId(), accessToken, params, HttpStatus.OK);
		Map<String, Object> responseMap = jsonParser.parseMap(result.getResponse().getContentAsString());
		compareResponseDataToAppUser(responseMap, standardUser);
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testFetchNonExistingUserById() throws Exception {
		String invalidUserId = "dup";
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		MvcResult result = fetchUser(invalidUserId, accessToken, params, HttpStatus.NOT_FOUND);
		Map<String, Object> responseMap = jsonParser.parseMap(result.getResponse().getContentAsString());
		assertEquals(responseMap.get("message"), ValidationErrorMessages.USER_NOT_FOUND_MESSAGE);
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testUpdateUserShouldSucceedWhenAllDataIsCorrect() throws Exception {
		params.setUsername(adminUser.getEmail());
		String adminAccessToken = getAccessToken(signIn(params, HttpStatus.OK));
		
		params.setUsername(standardUser.getEmail());
		Map<String, Object> oauthTokenResponse = signIn(params, HttpStatus.OK);
		String userAccessToken = oauthTokenResponse.get(accessTokenKey).toString();
		String userRefreshToken = oauthTokenResponse.get(refreshTokenKey).toString();

		long userAuthoritiesSize = standardUser.getAuthorities().size();
		long userRolesSize = standardUser.getRoles().size();
		String standardUserId = standardUser.getId();
		MvcResult result = updateAccount(userDataRequest, params, standardUserId, adminAccessToken, HttpStatus.OK);
		Map<String, Object> responseMap = jsonParser.parseMap(result.getResponse().getContentAsString());
		checkPresenceOfFieldsInResponse(responseMap);

		AppUser found = userRepository.findById(responseMap.get("userId").toString()).get();
		assertTrue(found.getAuthorities().size() > userAuthoritiesSize);
		assertTrue(found.getRoles().size() > userRolesSize);
		compareResponseDataToAppUser(responseMap, found);
		signOut(userAccessToken, HttpStatus.UNAUTHORIZED);
		params.setRefreshToken(userRefreshToken);
		refreshTokenRequest(params, HttpStatus.BAD_REQUEST);
		signIn(params, HttpStatus.UNAUTHORIZED);
		params.setUsername(found.getEmail());
		signIn(params, HttpStatus.OK);

		userDataRequest.setEnabled(false);
		result = updateAccount(userDataRequest, params, standardUserId, adminAccessToken, HttpStatus.OK);
		signIn(params, HttpStatus.UNAUTHORIZED);
		
		String firstAuthorityId = found.getAuthorities().iterator().next().getId();
		userDataRequest.setAuthorityIds(new HashSet<>(Collections.singletonList(firstAuthorityId)));
		userDataRequest.setRoleIds(Collections.emptySet());
		
		result = updateAccount(userDataRequest, params, standardUserId, adminAccessToken, HttpStatus.OK);
		found = userRepository.findById(responseMap.get("userId").toString()).get();
		int expectedAuthoritiesSize = 1;
		assertEquals(found.getAuthorities().size(), expectedAuthoritiesSize);
		assertTrue(found.getRoles().isEmpty());
		signOut(adminAccessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testUpdateUserShouldFailWhenEmailExists() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		String userId = standardUser.getId();
		userDataRequest.setEmail(adminUser.getEmail());
		MvcResult result = updateAccount(userDataRequest, params, userId, accessToken, HttpStatus.BAD_REQUEST);
		Map<String, Object> responseMap = jsonParser.parseMap(result.getResponse().getContentAsString());
		assertEquals(responseMap.get("message"), ValidationErrorMessages.USERNAME_EXISTS_MESSAGE);
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testUpdateUserShouldFailWhenUserIdDoesNotExist() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		String invalidUserId = "dup";
		MvcResult result = updateAccount(userDataRequest, params, invalidUserId, accessToken, HttpStatus.NOT_FOUND);
		Map<String, Object> responseMap = jsonParser.parseMap(result.getResponse().getContentAsString());
		assertEquals(responseMap.get("message"), ValidationErrorMessages.USER_NOT_FOUND_MESSAGE);
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testUpdateUserShouldFailWhenEnabledIsNull() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		String userId = standardUser.getId();
		userDataRequest.setEnabled(null);
		MvcResult result = updateAccount(userDataRequest, params, userId, accessToken, HttpStatus.BAD_REQUEST);

		Map<String, List<String>> errorMessages = extractValidationErrorMapFromResponse(result);
		int expectedErrorMessagesSize = 1;
		assertEquals(errorMessages.size(), expectedErrorMessagesSize);
		assertTrue(errorMessages.get("enabled").contains(ValidationErrorMessages.USER_ENABLED_NOT_EMPTY_MESSAGE));
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testUpdateUserShouldFailWhenAuthorityIdsIsNull() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		String userId = standardUser.getId();
		userDataRequest.setAuthorityIds(null);
		MvcResult result = updateAccount(userDataRequest, params, userId, accessToken, HttpStatus.BAD_REQUEST);

		Map<String, List<String>> errorMessages = extractValidationErrorMapFromResponse(result);
		int expectedErrorMessagesSize = 1;
		assertEquals(errorMessages.size(), expectedErrorMessagesSize);
		assertTrue(errorMessages.get("authorityIds").contains(ValidationErrorMessages.AUTHORITY_IDS_NOT_NULL_MESSAGE));
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testUpdateUserShouldFailWhenRoleIdsIsNull() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		String userId = standardUser.getId();
		userDataRequest.setRoleIds(null);
		MvcResult result = updateAccount(userDataRequest, params, userId, accessToken, HttpStatus.BAD_REQUEST);

		Map<String, List<String>> errorMessages = extractValidationErrorMapFromResponse(result);
		int expectedErrorMessagesSize = 1;
		assertEquals(errorMessages.size(), expectedErrorMessagesSize);
		assertTrue(errorMessages.get("roleIds").contains(ValidationErrorMessages.ROLE_IDS_NOT_NULL_MESSAGE));
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testSignOutUserShouldSucceedWhenUserExists() throws Exception {
		params.setUsername(adminUser.getEmail());
		String adminAccessToken = getAccessToken(signIn(params, HttpStatus.OK));
		params.setUsername(standardUser.getEmail());
		Map<String, Object> oauthTokenResponse = signIn(params, HttpStatus.OK);
		String userAccessToken = oauthTokenResponse.get(accessTokenKey).toString();
		String userRefreshToken = oauthTokenResponse.get(refreshTokenKey).toString();
		
		signUserOut(params, standardUser.getId(), adminAccessToken, HttpStatus.NO_CONTENT);
		
		signOut(userAccessToken, HttpStatus.UNAUTHORIZED);
		params.setRefreshToken(userRefreshToken);
		refreshTokenRequest(params, HttpStatus.BAD_REQUEST);
		signOut(adminAccessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testSignOutUserShouldReturnNotFoundWhenUserDoesNotExist() throws Exception {
		params.setUsername(adminUser.getEmail());
		String adminAccessToken = getAccessToken(signIn(params, HttpStatus.OK));
		params.setUsername(standardUser.getEmail());
		Map<String, Object> oauthTokenResponse = signIn(params, HttpStatus.OK);
		String userAccessToken = oauthTokenResponse.get(accessTokenKey).toString();
		
		String userId = "dup";
		signUserOut(params, userId , adminAccessToken, HttpStatus.NOT_FOUND);
		
		signOut(userAccessToken, HttpStatus.NO_CONTENT);
		signOut(adminAccessToken, HttpStatus.NO_CONTENT);
	}

	@Test
	public void testUpdateUserPasswordShouldSucceedWhenAllDataIsCorrect() throws Exception {
		params.setUsername(adminUser.getEmail());
		String adminAccessToken = getAccessToken(signIn(params, HttpStatus.OK));
		params.setUsername(standardUser.getEmail());
		Map<String, Object> oauthTokenResponse = signIn(params, HttpStatus.OK);
		String userAccessToken = oauthTokenResponse.get(accessTokenKey).toString();
		String userRefreshToken = oauthTokenResponse.get(refreshTokenKey).toString();
		
		MvcResult result = updatePassword(passwordRequest, params, standardUser.getId(), adminAccessToken, HttpStatus.OK);
		Map<String, Object> responseMap = jsonParser.parseMap(result.getResponse().getContentAsString());
		compareResponseDataToAppUser(responseMap, standardUser);
		
		signOut(userAccessToken, HttpStatus.UNAUTHORIZED);
		params.setRefreshToken(userRefreshToken);
		refreshTokenRequest(params, HttpStatus.BAD_REQUEST);
		signIn(params, HttpStatus.UNAUTHORIZED);
		params.setPassword(newNonHashedPassword);
		oauthTokenResponse = signIn(params, HttpStatus.OK);
		userAccessToken = oauthTokenResponse.get(accessTokenKey).toString();
		signOut(userAccessToken, HttpStatus.NO_CONTENT);
		signOut(adminAccessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testUpdateUserPasswordShouldFailWhenPasswordIsIncorrect() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		passwordRequest.setPassword("invalid");
		MvcResult result = updatePassword(passwordRequest, params, standardUser.getId(), accessToken, HttpStatus.BAD_REQUEST);

		Map<String, List<String>> errorMessages = extractValidationErrorMapFromResponse(result);
		int expectedErrorMessagesSize = 2;
		assertEquals(errorMessages.size(), expectedErrorMessagesSize);
		assertTrue(errorMessages.get("other").contains(ValidationErrorMessages.PASSWORDS_NOT_EQUAL_MESSAGE));
		assertTrue(errorMessages.get("password").contains(ValidationErrorMessages.INVALID_PASSWORD_MESSAGE));
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testUpdateUserPasswordShouldFailWhenPasswordIsNull() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		passwordRequest.setPassword(null);
		MvcResult result = updatePassword(passwordRequest, params, standardUser.getId(), accessToken, HttpStatus.BAD_REQUEST);

		Map<String, List<String>> errorMessages = extractValidationErrorMapFromResponse(result);
		int expectedErrorMessagesSize = 2;
		assertEquals(errorMessages.size(), expectedErrorMessagesSize);
		assertTrue(errorMessages.get("other").contains(ValidationErrorMessages.PASSWORDS_NOT_EQUAL_MESSAGE));
		assertTrue(errorMessages.get("password").contains(ValidationErrorMessages.PASSWORD_NOT_EMPTY_MESSAGE));
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testUpdateUserPasswordShouldFailWhenPasswordConfirmationIsIncorrect() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		passwordRequest.setPasswordConfirmation("invalid");
		MvcResult result = updatePassword(passwordRequest, params, standardUser.getId(), accessToken, HttpStatus.BAD_REQUEST);

		Map<String, List<String>> errorMessages = extractValidationErrorMapFromResponse(result);
		int expectedErrorMessagesSize = 2;
		assertEquals(errorMessages.size(), expectedErrorMessagesSize);
		assertTrue(errorMessages.get("other").contains(ValidationErrorMessages.PASSWORDS_NOT_EQUAL_MESSAGE));
		assertTrue(errorMessages.get("passwordConfirmation").contains(ValidationErrorMessages.INVALID_PASSWORD_CONFIRMATION_MESSAGE));
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}

	@Test
	public void testUpdateUserPasswordShouldFailWhenPasswordConfirmationIsNull() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		passwordRequest.setPasswordConfirmation(null);
		MvcResult result = updatePassword(passwordRequest, params, standardUser.getId(), accessToken, HttpStatus.BAD_REQUEST);

		Map<String, List<String>> errorMessages = extractValidationErrorMapFromResponse(result);
		int expectedErrorMessagesSize = 2;
		assertEquals(errorMessages.size(), expectedErrorMessagesSize);
		assertTrue(errorMessages.get("other").contains(ValidationErrorMessages.PASSWORDS_NOT_EQUAL_MESSAGE));
		assertTrue(errorMessages.get("passwordConfirmation").contains(ValidationErrorMessages.PASSWORD_CONFIRMATION_NOT_EMPTY_MESSAGE));
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testUpdateUserPasswordShouldFailWhenUserIdDoesNotExist() throws Exception {
		String invalidUserId = "fup";
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		MvcResult result = updatePassword(passwordRequest, params, invalidUserId, accessToken, HttpStatus.NOT_FOUND);
		Map<String, Object> responseMap = jsonParser.parseMap(result.getResponse().getContentAsString());
		assertEquals(responseMap.get("message"), ValidationErrorMessages.USER_NOT_FOUND_MESSAGE);
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testDeleteUserShouldSucceedWhenUserExists() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		String userId = standardUser.getId();
		deleteUser(userId, accessToken, params, HttpStatus.NO_CONTENT);
		assertFalse(userRepository.findById(userId).isPresent());
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testDeleteUserShouldFailWhenUserDoesNotExist() throws Exception {
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		String userId = "dup";
		deleteUser(userId, accessToken, params, HttpStatus.NOT_FOUND);
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testAccessToEndpointsByStandardUser() throws Exception {
		params.setUsername(standardUser.getEmail());
		String userId = standardUser.getId();
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		deleteUser(standardUser.getId(), accessToken, params, HttpStatus.FORBIDDEN);
		createAccount(userRequest, params, accessToken, HttpStatus.FORBIDDEN);
		updateAccount(userDataRequest, params, userId, accessToken, HttpStatus.FORBIDDEN);
		updatePassword(passwordRequest, params, standardUser.getId(), accessToken, HttpStatus.FORBIDDEN);
		getUsers(accessToken, params, HttpStatus.FORBIDDEN, Optional.empty(), Optional.empty(), Optional.empty(), Optional.empty());
		fetchUser(standardUser.getId(), accessToken, params, HttpStatus.FORBIDDEN);
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	private void deleteUser(String userId, String accessToken, OAuthClientParams params, HttpStatus expectedHttpStatus) throws Exception {
		MultiValueMap<String, String> paramsMap = new LinkedMultiValueMap<>();
		paramsMap.add("client_id", params.getClientId());
		mvc.perform(delete("/api/admin/users/delete/" + userId)
				.with(httpBasic(params.getClientId(), params.getClientDetailsPassword()))
				.header("Authorization", "Bearer " + accessToken)
				.contentType(MediaType.APPLICATION_JSON)
				.params(paramsMap)
				.accept(MediaType.APPLICATION_JSON))
		.andExpect(status().is(expectedHttpStatus.value()))
		.andReturn();
	}

	private MvcResult fetchUser(String id, String accessToken, OAuthClientParams params, HttpStatus expectedHttpStatus) throws Exception {
		MultiValueMap<String, String> paramsMap = new LinkedMultiValueMap<>();
		paramsMap.add("client_id", params.getClientId());
		return mvc.perform(get("/api/admin/users/show/" + id)
				.with(httpBasic(params.getClientId(), params.getClientDetailsPassword()))
				.header("Authorization", "Bearer " + accessToken)
				.contentType(MediaType.APPLICATION_JSON)
				.params(paramsMap)
				.accept(MediaType.APPLICATION_JSON))
		.andExpect(status().is(expectedHttpStatus.value()))
		.andReturn();
	}

	@SuppressWarnings("unchecked")
	private void testPaginationOfUsers(Optional<String> search, OAuthClientParams params, Optional<String> SearchBy, Optional<Integer> perPage, List<AppUser> users) throws Exception, UnsupportedEncodingException {
		int numberOfElementsPerPage = (!perPage.isPresent()) ? PER_PAGE : perPage.get();
		int pagesNum = users.size() / numberOfElementsPerPage;
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		
		for (int i = 0; i <= pagesNum; i++) {
			MvcResult result = getUsers(accessToken, params, HttpStatus.OK, Optional.of(i), perPage, search, SearchBy);
			
			Map<String, Object> responseMap = jsonParser.parseMap(result.getResponse().getContentAsString());
			List<Map<String, Object>> results = ((List<?>) responseMap.get("content")).stream().map(obj ->
					(Map<String, Object>)obj).collect(Collectors.toList());
			
			int toIndex = i * numberOfElementsPerPage + numberOfElementsPerPage;
			List<AppUser> subList = users.subList(i * numberOfElementsPerPage, Math.min(toIndex, users.size()));
			
			assertEquals(subList.size(), results.size());
			
			for (int j = 0; j < subList.size(); j++) {
				Map<String, Object> responseObj = results.get(j);
				AppUser user = subList.get(j);
				compareResponseDataToAppUser(responseObj, user);
			}
		}
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	private MvcResult getUsers(String accessToken, OAuthClientParams params, HttpStatus expectedHttpStatus, Optional<Integer> page, Optional<Integer> perPage, Optional<String> search, Optional<String> searchBy) throws Exception {
		StringBuilder queryStringBuilder = new StringBuilder("");
		if (page.isPresent() && page.get() > 0) {
			queryStringBuilder.append("/");
			queryStringBuilder.append(page.get());
		}
		appendToQueryString(queryStringBuilder, Optional.of("search"), search);
		appendToQueryString(queryStringBuilder, Optional.of("searchBy"), searchBy);
		appendToQueryString(queryStringBuilder, Optional.of("per_page"), perPage);
		MultiValueMap<String, String> paramsMap = new LinkedMultiValueMap<>();
		paramsMap.add("client_id", params.getClientId());
		return mvc.perform(get("/api/admin/users/list" + queryStringBuilder.toString())
				.with(httpBasic(params.getClientId(), params.getClientDetailsPassword()))
				.header("Authorization", "Bearer " + accessToken)
				.params(paramsMap)
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON))
		.andExpect(status().is(expectedHttpStatus.value()))
		.andReturn();
	}
	
	private void appendToQueryString(StringBuilder queryStringBuilder, Optional<String> parameterName, Optional<?> parameterValue) {
		if (parameterValue.isPresent()) {
			String qs = queryStringBuilder.toString();
			queryStringBuilder.append(!qs.contains("?") ? "?" : "&");
			queryStringBuilder.append(parameterName.get());
			queryStringBuilder.append("=");
			queryStringBuilder.append(parameterValue.get().toString());
		}
	}

	@SuppressWarnings("unchecked")
	private void compareResponseDataToAppUser(Map<String, Object> responseMap, AppUser user) {
		List<String> authorityIds = extractListOfLongsFromMapWithField(responseMap, "authorities");
		List<String> roleIds = extractListOfLongsFromMapWithField(responseMap, "roles");
		
		UserData userData = new UserData();
		Map<String, Object> userDataMap = (Map<String, Object>) responseMap.get("userData");
		userData.setEmail(userDataMap.get("email").toString());
		
		assertEquals(user.getUserData().getEmail(), userData.getEmail());
		assertEquals(user.getEnabled(), (Boolean)responseMap.get("enabled"));
		user.getAuthorities().forEach(a -> {
			assertTrue(authorityIds.contains(a.getId()));
		});
		
		user.getRoles().forEach(r -> {
			assertTrue(roleIds.contains(r.getId()));
		});
	}

	private List<AppUser> createAppUsers(int usersNum, Optional<String> emailAddress) {
		return IntStream.range(0, usersNum).mapToObj(i -> {
			AppUser user = new AppUser();
			user.setEmail(emailAddress.isPresent() ? "test" + i + "@" + emailAddress.get() : faker.internet().emailAddress());
			user.setEnabled(true);
			//user.setLastAccountUpdateDate(Date.from(Instant.now()));
			user.setPassword(hashedPassword);
			user.getAuthorities().addAll(standardUser.getAuthorities());
			user.getRoles().addAll(standardUser.getRoles());
			userRepository.save(user);
			return user;
		}).collect(Collectors.toList());
	}
	
	@SuppressWarnings("unchecked")
	private List<String> extractListOfLongsFromMapWithField(Map<String, Object> responseMap, String fieldName) {
		return ((List<?>) responseMap.get(fieldName)).stream().map(m -> {
			Map<String, Object> authorityMap = (Map<String, Object>)m;
			return authorityMap.get("id").toString();
		}).collect(Collectors.toList());
	}
	
	private void checkPresenceOfFieldsInResponse(Map<String, Object> responseMap) {
		int expectedKeySetSize = 6;
		assertTrue(responseMap.containsKey("userId"));
		assertTrue(responseMap.containsKey("userData"));
		assertTrue(responseMap.containsKey("enabled"));
		assertTrue(responseMap.containsKey("lastAccountUpdateDate"));
		assertTrue(responseMap.containsKey("authorities"));
		assertTrue(responseMap.containsKey("roles"));
		assertFalse(responseMap.containsKey("password"));
		assertFalse(responseMap.containsKey("passwordConfirmation"));
		assertEquals(responseMap.keySet().size(), expectedKeySetSize);
	}
	
	private MvcResult createAccount(UserModelRequest body, OAuthClientParams params, String accessToken, HttpStatus expectedHttpStatus) throws Exception {
		String requestBodyString = objectMapper.writeValueAsString(body);
		MultiValueMap<String, String> paramsMap = new LinkedMultiValueMap<>();
		paramsMap.add("client_id", params.getClientId());
		return mvc.perform(post("/api/admin/users/create")
				.with(httpBasic(params.getClientId(), params.getClientDetailsPassword()))
				.header("Authorization", "Bearer " + accessToken)
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON)
				.params(paramsMap)
				.content(requestBodyString))
		.andExpect(status().is(expectedHttpStatus.value()))
		.andReturn();
	}
	
	private MvcResult updateAccount(UserDataExtendedModel body, OAuthClientParams params, String userId, String accessToken, HttpStatus expectedHttpStatus) throws Exception {
		String requestBodyString = objectMapper.writeValueAsString(body);
		MultiValueMap<String, String> paramsMap = new LinkedMultiValueMap<>();
		paramsMap.add("client_id", params.getClientId());
		return mvc.perform(put("/api/admin/users/update/" + userId)
				.with(httpBasic(params.getClientId(), params.getClientDetailsPassword()))
				.header("Authorization", "Bearer " + accessToken)
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON)
				.params(paramsMap)
				.content(requestBodyString))
		.andExpect(status().is(expectedHttpStatus.value()))
		.andReturn();
	}
	
	private MvcResult updatePassword(PasswordRequestModel body, OAuthClientParams params, String userId, String accessToken, HttpStatus expectedHttpStatus) throws Exception {
		String requestBodyString = objectMapper.writeValueAsString(body);
		MultiValueMap<String, String> paramsMap = new LinkedMultiValueMap<>();
		paramsMap.add("client_id", params.getClientId());
		return mvc.perform(put("/api/admin/users/update_password/" + userId)
				.with(httpBasic(params.getClientId(), params.getClientDetailsPassword()))
				.header("Authorization", "Bearer " + accessToken)
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON)
				.params(paramsMap)
				.content(requestBodyString))
		.andExpect(status().is(expectedHttpStatus.value()))
		.andReturn();
	}
	
	private MvcResult signUserOut(OAuthClientParams params, String userId, String adminAccessToken, HttpStatus expectedHttpStatus) throws Exception {
		MultiValueMap<String, String> paramsMap = new LinkedMultiValueMap<>();
		paramsMap.add("client_id", params.getClientId());
		return mvc.perform(post("/api/admin/users/sign_user_out/" + userId)
				.with(httpBasic(params.getClientId(), params.getClientDetailsPassword()))
				.header("Authorization", "Bearer " + adminAccessToken)
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON)
				.params(paramsMap))
		.andExpect(status().is(expectedHttpStatus.value()))
		.andReturn();
	}
}
