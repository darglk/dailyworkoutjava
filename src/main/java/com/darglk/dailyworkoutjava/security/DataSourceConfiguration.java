package com.darglk.dailyworkoutjava.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.jdbc.DataSourceBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;

import javax.sql.DataSource;

@Configuration
public class DataSourceConfiguration {

	@Value("${spring.datasource.username}")
	private String username;

	@Value("${spring.datasource.password}")
	private String password;

	@Value("${spring.datasource.hikari.jdbc-url}")
	private String dbUrl;

	@Bean
	@Primary
	@ConfigurationProperties(prefix = "spring.datasource")
	public DataSource oauthDataSource() {
		DataSource datasource = DataSourceBuilder.create()
				.username(username)
				.password(password)
				.url(dbUrl)
				.build();
		return datasource;
	}

	/**
	 * JdbcClientDetailsService bean.
	 * 
	 * @return JdbcClientDetailsService.
	 */
	@Bean
	public JdbcClientDetailsService jdbcClientDetailsService() {
		return new JdbcClientDetailsService(oauthDataSource());
	}
}
