package com.darglk.dailyworkoutjava.security;

import com.darglk.dailyworkoutjava.domain.user.repository.*;
import com.darglk.dailyworkoutjava.domain.user.service.UserService;
import com.darglk.dailyworkoutjava.domain.user.service.UserServiceImpl;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.*;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.connection.RedisStandaloneConfiguration;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenApprovalStore;
import org.springframework.security.oauth2.provider.approval.TokenStoreUserApprovalHandler;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;
import org.springframework.security.oauth2.provider.code.JdbcAuthorizationCodeServices;
import org.springframework.security.oauth2.provider.endpoint.TokenEndpointAuthenticationFilter;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.redis.RedisTokenStore;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;

import javax.sql.DataSource;
import java.util.Arrays;

/**
 * Authorization Server config class.
 * @author Dariusz Kulig
 *
 */
@ConfigurationProperties("application")
@Configuration
@EnableAuthorizationServer
@DependsOn("dataSourceConfiguration")
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter {

	/**
	 * redisHost - redis server host name.
	 */
	@Value("${spring.redis.host}")
	private String redisHost;

	/**
	 * redisPort - redis server port number.
	 */
	@Value("${spring.redis.port}")
	private int redisPort;

	@Value("${spring.redis.password}")
	private String redisPassword;
	
	/**
	 * authenticationManager - Authentication manager needed for password grant type.
	 */
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private RoleRepository roleRepository;
	
	@Autowired
	private AuthorityRepository authorityRepository;

//	@Autowired
//	private UserService userDetailsService;

	/**
	 * Redis token store bean.
	 * @return redis connection factory instance.
	 */
	@Bean
	public RedisConnectionFactory redisConnectionFactory() {
		RedisStandaloneConfiguration config = new RedisStandaloneConfiguration();
		config.setHostName(redisHost);
		config.setPort(redisPort);
		config.setPassword(redisPassword);
		return new JedisConnectionFactory(config);
	}

	/**
	 * Oauth data source bean.
	 * @return oauth data source.
	 */
	@Autowired
	private DataSource dataSource;

	@Autowired
	private AccountActivationTokenRepository accountActivationTokenRepository;

	@Autowired
	private JavaMailSender mailSender;

	@Autowired
	private PasswordTokenRepository passwordTokenRepository;

	@Autowired
	private JdbcClientDetailsService clientDetailsService;
	
//	@Autowired
//	public void setClientDetailsService(JdbcClientDetailsService clientDetailsService) {
//		this.clientDetailsService = clientDetailsService;
//	}
	
	@Autowired
	public void setDataSource(@Lazy DataSource dataSource) {
		this.dataSource = dataSource;
	}
	
	public UserRepository getUserRepository() {
		return userRepository;
	}



	public void setUserRepository(@Lazy UserRepository userRepository) {
		this.userRepository = userRepository;
	}



	public RoleRepository getRoleRepository() {
		return roleRepository;
	}



	public void setRoleRepository(@Lazy RoleRepository roleRepository) {
		this.roleRepository = roleRepository;
	}



	public AuthorityRepository getAuthorityRepository() {
		return authorityRepository;
	}



	public void setAuthorityRepository(@Lazy AuthorityRepository authorityRepository) {
		this.authorityRepository = authorityRepository;
	}



	public AccountActivationTokenRepository getAccountActivationTokenRepository() {
		return accountActivationTokenRepository;
	}



	public void setAccountActivationTokenRepository(@Lazy AccountActivationTokenRepository accountActivationTokenRepository) {
		this.accountActivationTokenRepository = accountActivationTokenRepository;
	}



	public JavaMailSender getMailSender() {
		return mailSender;
	}



	public void setMailSender(@Lazy JavaMailSender mailSender) {
		this.mailSender = mailSender;
	}



	public PasswordTokenRepository getPasswordTokenRepository() {
		return passwordTokenRepository;
	}



	public void setPasswordTokenRepository(@Lazy PasswordTokenRepository passwordTokenRepository) {
		this.passwordTokenRepository = passwordTokenRepository;
	}

	

	

	

	@Bean
	public TokenEnhancer tokenEnhancer() {
		return new OAuthTokenEnhancer();
	}

	/**
	 * ApprovalStore bean.
	 * @return JdbcApprovalStore.
	 */
	@Bean
	public ApprovalStore approvalStore() {
		TokenApprovalStore store = new TokenApprovalStore();
		store.setTokenStore(tokenStore());
		return store;
	}

	/**
	 * TokenStoreApprovalHandler bean.
	 * @return TokenStoreUserApprovalHandler instance.
	 */
	@Bean
	public TokenStoreUserApprovalHandler userApprovalHandler() {
		TokenStoreUserApprovalHandler handler = new TokenStoreUserApprovalHandler();
		handler.setTokenStore(tokenStore());
		handler.setRequestFactory(new DefaultOAuth2RequestFactory(clientDetailsService));
		handler.setClientDetailsService(clientDetailsService);
		return handler;
	}

	/**
	 * ProviderManager bean.
	 * @return instance of PreAuthenticatedAuthenticationProvider.
	 */
	@Bean
	public ProviderManager preAuthenticationProvider() {
		PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
		provider.setPreAuthenticatedUserDetailsService(new UserDetailsByNameServiceWrapper<>(userService()));
		return new ProviderManager(Arrays.asList(provider));
	}

	/**
	 * AuthorizationServerTokenServices bean.
	 * @return instance of DefaultTokenServices.
	 */
	@Bean
	@Primary
	public AuthorizationServerTokenServices oauthServerTokenServices() {
		DefaultTokenServices tokenServices = new DefaultTokenServices();
		tokenServices.setClientDetailsService(clientDetailsService);
		tokenServices.setReuseRefreshToken(false);
		tokenServices.setSupportRefreshToken(true);
		tokenServices.setTokenStore(tokenStore());
		tokenServices.setAuthenticationManager(preAuthenticationProvider());
		tokenServices.setTokenEnhancer(tokenEnhancer());
		return tokenServices;
	}

	/**
	 * Token store bean.
	 * @return JdbcTokenStore.
	 */
	@Bean
	public TokenStore tokenStore() {
		return new RedisTokenStore(redisConnectionFactory());
	}
	
	@Bean
	public UserService userService() {
		return new UserServiceImpl();
		//return null;
	}

	/**
	 * Authorization code services bean.
	 * @return jdbc authorization service codes services.
	 */
	@Bean
	public AuthorizationCodeServices authorizationCodeServices() {
		return new JdbcAuthorizationCodeServices(dataSource);
	}

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients.withClientDetails(clientDetailsService);
	}
	
	@Bean
	public TokenEndpointAuthenticationFilter authenticationFilter() {
		return new AuthenticationFilter(authenticationManager, oAuth2RequestFactory(), userRepository);
	}
	
	@Bean
	public OAuth2RequestFactory oAuth2RequestFactory() {
		DefaultOAuth2RequestFactory requestFactory = new DefaultOAuth2RequestFactory(clientDetailsService);
		return requestFactory ;
	}

	@Override
	public void configure(AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
		//oauthServer.addTokenEndpointAuthenticationFilter(authenticationFilter());
		//oauthServer.tokenEndpointAuthenticationFilters(Arrays.asList(authenticationFilter()));
		//oauthServer.addTokenEndpointAuthenticationFilter(authenticationFilter());
		
	}

	@Override
	public final void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		DefaultTokenServices tokenServices = (DefaultTokenServices)oauthServerTokenServices();
		tokenServices.setClientDetailsService(clientDetailsService);
		endpoints.approvalStore(approvalStore()).userApprovalHandler(userApprovalHandler())
		.pathMapping("/oauth/token", "/api/sign_in")
				.authenticationManager(authenticationManager).authorizationCodeServices(authorizationCodeServices())
				.tokenServices(tokenServices)
				.tokenEnhancer(tokenEnhancer());
	}
}
