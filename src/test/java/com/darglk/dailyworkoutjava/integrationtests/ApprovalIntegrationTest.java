package com.darglk.dailyworkoutjava.integrationtests;

import com.darglk.dailyworkoutjava.DailyworkoutjavaApplication;
import com.darglk.dailyworkoutjava.domain.user.entity.*;
import com.darglk.dailyworkoutjava.domain.user.repository.AuthorityRepository;
import com.darglk.dailyworkoutjava.domain.user.repository.RoleRepository;
import com.darglk.dailyworkoutjava.domain.user.repository.UserRepository;
import com.darglk.dailyworkoutjava.integrationtests.utils.OAuthClientParams;
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
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringExtension.class)
@SpringBootTest(
	webEnvironment = WebEnvironment.DEFINED_PORT,
	classes = DailyworkoutjavaApplication.class)
@AutoConfigureMockMvc
@TestPropertySource(locations = "classpath:application-test.properties")
@DirtiesContext(classMode = ClassMode.AFTER_CLASS)
public class ApprovalIntegrationTest extends BaseIntegrationTest {

	private AppUser standardUser;
	
	private UserRepository userRepository;

	private AuthorityRepository authorityRepository;

	private RoleRepository roleRepository;
	
	private ClientDetails clientDetails;
	
	private String clientId = "oauth_client_id";

	private OAuthClientParams params;
	
	private JdbcClientDetailsService clientDetailsService;

	private AppUser adminUser;
	
	private ApprovalStore approvalStore;
	
	@Autowired
	public ApprovalIntegrationTest(UserRepository userRepository, AuthorityRepository authorityRepository,
			RoleRepository roleRepository, JdbcClientDetailsService clientDetailsService, ApprovalStore approvalStore) {
		this.userRepository = userRepository;
		this.authorityRepository = authorityRepository;
		this.roleRepository = roleRepository;
		this.clientDetailsService = clientDetailsService;
		this.approvalStore = approvalStore;
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
		userRepository.deleteAll();
		authorityRepository.deleteAll();
		authorityRepository.deleteAll();
		roleRepository.deleteAll();
		clientDetailsService.listClientDetails().forEach(client -> {
			clientDetailsService.removeClientDetails(client.getClientId());
		});
	}
	
	@Test
	public void testShowMyApprovals() throws Exception {
		params.setUsername(standardUser.getEmail());
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		MvcResult mvcResult = getApprovals(params, accessToken, HttpStatus.OK);
		List<Approval> approvalList = approvalStore.getApprovals(standardUser.getEmail(), clientId).stream().collect(Collectors.toList());

		List<?> approvalResponseList = (List<?>)(jsonParser.parseList(mvcResult.getResponse().getContentAsString()));
		assertEquals(approvalResponseList.size(), approvalList.size());
	}
	
	@Test
	public void testShowApprovalsForAdmin() throws Exception {
		params.setUsername(standardUser.getEmail());
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		params.setUsername(adminUser.getEmail());
		String adminAccessToken = getAccessToken(signIn(params, HttpStatus.OK));
		MvcResult mvcResult = getApprovalsForAdmin(params, standardUser.getId(), accessToken, HttpStatus.FORBIDDEN);
		mvcResult = getApprovalsForAdmin(params, standardUser.getId(), adminAccessToken, HttpStatus.OK);
		List<Approval> approvalList = approvalStore.getApprovals(standardUser.getEmail(), clientId).stream().collect(Collectors.toList());

		List<?> approvalResponseList = (List<?>)(jsonParser.parseList(mvcResult.getResponse().getContentAsString()));
		assertEquals(approvalResponseList.size(), approvalList.size());
		signOut(adminAccessToken, HttpStatus.NO_CONTENT);
		signOut(accessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testDeleteApprovalByAdmin() throws Exception {
		params.setUsername(standardUser.getEmail());
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		params.setUsername(adminUser.getEmail());
		String adminAccessToken = getAccessToken(signIn(params, HttpStatus.OK));
		List<Approval> approvalList = approvalStore.getApprovals(standardUser.getEmail(), clientId).stream().collect(Collectors.toList());
		assertTrue(approvalList.size() > 0);
		Approval approval = approvalList.get(0);
		deleteApprovalByAdmin(params, approval, accessToken, HttpStatus.FORBIDDEN);
		deleteApprovalByAdmin(params, approval, adminAccessToken, HttpStatus.NO_CONTENT);
		
		approvalList = approvalStore.getApprovals(standardUser.getEmail(), clientId).stream().collect(Collectors.toList());
		assertFalse(approvalList.contains(approval));
		signOut(adminAccessToken, HttpStatus.NO_CONTENT);
	}
	
	@Test
	public void testDeleteApproval() throws Exception {
		params.setUsername(standardUser.getEmail());
		String accessToken = getAccessToken(signIn(params, HttpStatus.OK));
		params.setUsername(adminUser.getEmail());
		String adminAccessToken = getAccessToken(signIn(params, HttpStatus.OK));
		List<Approval> approvalList = approvalStore.getApprovals(standardUser.getEmail(), clientId).stream().collect(Collectors.toList());
		List<Approval> adminApprovals = approvalStore.getApprovals(adminUser.getEmail(), clientId).stream().collect(Collectors.toList());
		assertTrue(approvalList.size() > 0);
		assertTrue(adminApprovals.size() > 0);
		
		Approval approval = adminApprovals.get(0);
		deleteApproval(params, approval , accessToken, HttpStatus.NOT_FOUND);
		approval = approvalList.get(0);
		deleteApproval(params, approval , accessToken, HttpStatus.NO_CONTENT);
		approvalList = approvalStore.getApprovals(standardUser.getEmail(), clientId).stream().collect(Collectors.toList());
		assertFalse(approvalList.contains(approval));
		signOut(adminAccessToken, HttpStatus.NO_CONTENT);
	}
	
	private MvcResult getApprovals(OAuthClientParams params, String accessToken, HttpStatus expectedHttpStatus) throws Exception {
		MultiValueMap<String, String> paramsMap = new LinkedMultiValueMap<>();
		paramsMap.add("client_id", params.getClientId());
		return mvc.perform(get("/api/approvals/list")
				.with(httpBasic(params.getClientId(), params.getClientDetailsPassword()))
				.header("Authorization", "Bearer " + accessToken)
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON)
				.params(paramsMap))
		.andExpect(status().is(expectedHttpStatus.value()))
		.andReturn();
	}
	
	private MvcResult deleteApproval(OAuthClientParams params, Approval approval, String accessToken, HttpStatus expectedHttpStatus) throws Exception {
		MultiValueMap<String, String> paramsMap = new LinkedMultiValueMap<>();
		paramsMap.add("client_id", params.getClientId());
		String approvalString = objectMapper.writeValueAsString(approval);
		return mvc.perform(post("/api/approvals/delete")
				.with(httpBasic(params.getClientId(), params.getClientDetailsPassword()))
				.header("Authorization", "Bearer " + accessToken)
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON)
				.params(paramsMap)
				.content(approvalString))
		.andExpect(status().is(expectedHttpStatus.value()))
		.andReturn();
	}
	
	private MvcResult getApprovalsForAdmin(OAuthClientParams params, String userId, String accessToken, HttpStatus expectedHttpStatus) throws Exception {
		MultiValueMap<String, String> paramsMap = new LinkedMultiValueMap<>();
		paramsMap.add("client_id", params.getClientId());
		return mvc.perform(get("/api/admin/approvals/list/" + userId)
				.with(httpBasic(params.getClientId(), params.getClientDetailsPassword()))
				.header("Authorization", "Bearer " + accessToken)
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON)
				.params(paramsMap))
		.andExpect(status().is(expectedHttpStatus.value()))
		.andReturn();
	}
	
	private MvcResult deleteApprovalByAdmin(OAuthClientParams params, Approval approval, String accessToken, HttpStatus expectedHttpStatus) throws Exception {
		MultiValueMap<String, String> paramsMap = new LinkedMultiValueMap<>();
		paramsMap.add("client_id", params.getClientId());
		String approvalString = objectMapper.writeValueAsString(approval);
		return mvc.perform(post("/api/admin/approvals/delete")
				.with(httpBasic(params.getClientId(), params.getClientDetailsPassword()))
				.header("Authorization", "Bearer " + accessToken)
				.contentType(MediaType.APPLICATION_JSON)
				.accept(MediaType.APPLICATION_JSON)
				.params(paramsMap)
				.content(approvalString))
		.andExpect(status().is(expectedHttpStatus.value()))
		.andReturn();
	}
}
