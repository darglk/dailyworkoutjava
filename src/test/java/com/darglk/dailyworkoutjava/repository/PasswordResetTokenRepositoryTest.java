package com.darglk.dailyworkoutjava.repository;

import com.darglk.dailyworkoutjava.domain.user.entity.AppUser;
import com.darglk.dailyworkoutjava.domain.user.entity.PasswordResetToken;
import com.darglk.dailyworkoutjava.domain.user.repository.PasswordTokenRepository;
import com.darglk.dailyworkoutjava.domain.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.EmbeddedDatabaseConnection;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.validation.ConstraintViolationException;
import java.time.Instant;
import java.util.Date;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@DataJpaTest
@AutoConfigureTestDatabase(connection = EmbeddedDatabaseConnection.H2)
@TestPropertySource(locations = "classpath:application-repository-test.properties")
@DirtiesContext(classMode = ClassMode.AFTER_EACH_TEST_METHOD)
public class PasswordResetTokenRepositoryTest {

	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private PasswordTokenRepository passwordResetTokenRepository;
	
	private AppUser appUser;
	
	private PasswordResetToken passwordResetToken;
	
	@BeforeEach
	public void setUp() {
		appUser = new AppUser();
		appUser.setAuthorities(new HashSet<>());
		appUser.setRoles(new HashSet<>());
		String email = "test@test.com";
		appUser.setEmail(email );
		appUser.setEnabled(true);
		appUser.setLastPasswordResetDate(Date.from(Instant.now()));
		String password = "password";
		appUser.setPassword(password );
		appUser = userRepository.save(appUser);
		
		passwordResetToken = new PasswordResetToken();
		passwordResetToken.setToken("activationToken");
		passwordResetToken.setUser(appUser);
		passwordResetToken.setExpiryDate(Date.from(Instant.now()));
	}
	
	@Test
	public void testSavePasswordToken() {
		PasswordResetToken savedToken = passwordResetTokenRepository.save(passwordResetToken);
		assertNotNull(savedToken.getId());
		assertEquals(passwordResetToken.getToken(), savedToken.getToken());
		assertEquals(passwordResetToken.getUser(), savedToken.getUser());
		
		PasswordResetToken found = passwordResetTokenRepository.findByToken(passwordResetToken.getToken());
		assertEquals(savedToken, found);
		found = passwordResetTokenRepository.findByUser(appUser);
		assertEquals(savedToken, found);
	}
	
	@Test
	public void testSavePasswordTokenWithNullUserShouldThrowException() {
		passwordResetToken.setUser(null);
		assertThrows(ConstraintViolationException.class, () -> {
			passwordResetTokenRepository.save(passwordResetToken);
			passwordResetTokenRepository.findAll();
		});
	}
	
	@Test
	public void testSavePasswordTokenWithNullTokenStringShouldThrowException() {
		passwordResetToken.setToken(null);
		assertThrows(ConstraintViolationException.class, () -> {
			passwordResetTokenRepository.save(passwordResetToken);
			passwordResetTokenRepository.findAll();
		});
	}
	
	@Test
	public void testSavePasswordTokenWithNullExpiryDateShouldThrowException() {
		passwordResetToken.setExpiryDate(null);
		assertThrows(ConstraintViolationException.class, () -> {
			passwordResetTokenRepository.save(passwordResetToken);
			passwordResetTokenRepository.findAll();
		});
	}
}
