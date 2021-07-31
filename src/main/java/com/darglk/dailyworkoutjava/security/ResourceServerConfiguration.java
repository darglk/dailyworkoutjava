package com.darglk.dailyworkoutjava.security;

import com.darglk.dailyworkoutjava.domain.user.entity.RoleName;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.hierarchicalroles.RoleHierarchy;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.expression.OAuth2WebSecurityExpressionHandler;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.web.access.expression.WebExpressionVoter;

import java.util.ArrayList;
import java.util.List;

/**
 * Configuration class used for oauth_resource server.
 * @author Dariusz Kulig
 *
 */
@EnableResourceServer
@Configuration
public class ResourceServerConfiguration extends ResourceServerConfigurerAdapter {

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

	/**
	 * tokenStore - used for caching access and refresh tokens.
	 */
	@Autowired
	private TokenStore tokenStore;
	
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}
	
	@Override
	public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
		resources.resourceId("oauth_server_api").tokenStore(tokenStore);
	}

	@Bean
    public RoleHierarchyImpl roleHierarchy() {
        RoleHierarchyImpl roleHierarchy = new RoleHierarchyImpl();
        roleHierarchy.setHierarchy(RoleName.ROLE_ADMIN.name() + " > " + RoleName.ROLE_USER);
        return roleHierarchy;
    }

    @Bean
    public RoleHierarchyVoter roleVoter() {
        return new RoleHierarchyVoter(roleHierarchy());
    }

    @Bean
    public AffirmativeBased defaultOauthDecisionManager(RoleHierarchy roleHierarchy) {
      List<AccessDecisionVoter<?>> decisionVoters = new ArrayList<>();
      OAuth2WebSecurityExpressionHandler expressionHandler = new OAuth2WebSecurityExpressionHandler();
      expressionHandler.setRoleHierarchy(roleHierarchy);
      WebExpressionVoter webExpressionVoter = new WebExpressionVoter();
      webExpressionVoter.setExpressionHandler(expressionHandler);
      decisionVoters.add(webExpressionVoter);
      decisionVoters.add(roleVoter());
      return new AffirmativeBased(decisionVoters);
    }
	
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests()
				.antMatchers("/api/users/forgot_password", "/api/users/reset_password", "/api/users/activate_account", "/api/users/sign_up").permitAll()
				.antMatchers("/api/admin/**", "/api/product/create", "/api/product/update", "/api/product/delete",
	            		"/api/order/delete", "/api/order/update", "/api/customer/delete").hasRole("ADMIN")
				.antMatchers("/v2/api-docs", "/configuration/**", "/swagger/**", "/webjars/**", "/swagger-ui.html", "/swagger-resources/**").permitAll()
				.accessDecisionManager(defaultOauthDecisionManager(roleHierarchy()))
				.antMatchers(HttpMethod.GET, "/**").access("#oauth2.hasScope('read')")
				.antMatchers(HttpMethod.POST, "/**").access("#oauth2.hasScope('write')")
				.antMatchers(HttpMethod.PATCH, "/**").access("#oauth2.hasScope('write')")
				.antMatchers(HttpMethod.PUT, "/**").access("#oauth2.hasScope('write')")
				.antMatchers(HttpMethod.DELETE, "/**").access("#oauth2.hasScope('write')")
				.antMatchers(HttpMethod.OPTIONS, "/oauth/token").permitAll()
				.and().cors()
				.and().csrf().disable();
	}
}