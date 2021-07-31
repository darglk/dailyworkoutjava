package com.darglk.dailyworkoutjava.security;

import com.darglk.dailyworkoutjava.domain.user.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * Configuration for web security.
 * 
 * @author Dariusz Kulig
 *
 */
@EnableWebSecurity
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

	/**
	 * Bean for authentication manager. Needed for password grant type.
	 * 
	 * @return AuthenticationManager instance.
	 */
	@Bean
	@Primary
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Autowired
	private UserService userService;

	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Override
	public void configure(WebSecurity web) throws Exception {
		web.ignoring().antMatchers("/webjars/**", "/resources/**");
	}

	@Override
	protected final void configure(HttpSecurity http) throws Exception {
		http.authorizeRequests().antMatchers("/api/users/forgot_password", "/api/users/reset_password").permitAll()
		.antMatchers("/api/admin/**").hasRole("ADMIN")
		.antMatchers("/v2/api-docs", "/configuration/**", "/swagger/**", "/webjars/**", "/swagger-ui.html", "/swagger-resources/**").permitAll()
		.and().authorizeRequests()
		.anyRequest().authenticated().and().userDetailsService(userDetailsServiceBean()).cors();

				
	}

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userService).passwordEncoder(passwordEncoder);
	}
}
