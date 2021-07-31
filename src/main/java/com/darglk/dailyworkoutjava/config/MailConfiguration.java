package com.darglk.dailyworkoutjava.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mail.javamail.MimeMessagePreparator;

import javax.mail.internet.MimeMessage;
import java.io.InputStream;

/**
 * Configuration for JavaMailSender instance
 * 
 * @author darglk
 *
 */
@Configuration
public class MailConfiguration {

	/**
	 * Bean method for JavaMailSender stub.
	 * 
	 * @return Stub of JavaMailSender instance.
	 */
	@Bean
	@Profile("test")
	public JavaMailSender javaMailSender() {
		return new JavaMailSender() {
			@Override
			public void send(SimpleMailMessage simpleMessage) throws MailException {
				System.out.println("Sending message...");
			}

			@Override
			public void send(SimpleMailMessage... simpleMessages) throws MailException {
			}

			@Override
			public MimeMessage createMimeMessage() {
				return null;
			}

			@Override
			public MimeMessage createMimeMessage(InputStream contentStream) throws MailException {
				return null;
			}

			@Override
			public void send(MimeMessage mimeMessage) throws MailException {
			}

			@Override
			public void send(MimeMessage... mimeMessages) throws MailException {
			}

			@Override
			public void send(MimeMessagePreparator mimeMessagePreparator) throws MailException {
			}

			@Override
			public void send(MimeMessagePreparator... mimeMessagePreparators) throws MailException {
			}
		};
	}

	/**
	 * Bean method for JavaMailSender instance. It should be invoked when
	 * application runs in production mode. Configuration for instance is defined in
	 * application.properties file.
	 * 
	 * @return JavaMailService instance.
	 */
	@Bean
	@Profile("default")
	public JavaMailSender javaMailSenderProd() {
		JavaMailSenderImpl mailSender = new JavaMailSenderImpl();
		return mailSender;
	}
}
