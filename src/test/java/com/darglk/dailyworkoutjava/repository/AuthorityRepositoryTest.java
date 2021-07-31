package com.darglk.dailyworkoutjava.repository;

import com.darglk.dailyworkoutjava.domain.user.entity.AppUser;
import com.darglk.dailyworkoutjava.domain.user.entity.Authority;
import com.darglk.dailyworkoutjava.domain.user.entity.AuthorityName;
import com.darglk.dailyworkoutjava.domain.user.repository.AuthorityRepository;
import com.darglk.dailyworkoutjava.domain.user.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.EmbeddedDatabaseConnection;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import javax.validation.ConstraintViolationException;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@DataJpaTest
@AutoConfigureTestDatabase(connection = EmbeddedDatabaseConnection.H2)
@TestPropertySource(locations = "classpath:application-repository-test.properties")
@DirtiesContext(classMode = ClassMode.AFTER_EACH_TEST_METHOD)
public class AuthorityRepositoryTest {

	@Autowired
	private AuthorityRepository authorityRepository;
	
	private Authority authority;

	private AppUser appUser;

	@Autowired
	private UserRepository userRepository;
	
	@BeforeEach
	public void setUp() {
		authority = new Authority();
		authority.setName(AuthorityName.CREATE_AUTHORITY);
		authority = authorityRepository.save(authority);
		
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
	}
	
	@Test
	public void testSaveAuthority() {
		Authority readAuthority = new Authority();
		AppUser foundUser = userRepository.findAppUserByUserDataEmail(appUser.getEmail());
		readAuthority.setName(AuthorityName.READ_AUTHORITY);
		
		
		readAuthority = authorityRepository.save(readAuthority);
		readAuthority.getUsers().add(foundUser);
		readAuthority.getUsers().add(foundUser);
		foundUser.getAuthorities().add(readAuthority);
		foundUser.getAuthorities().add(readAuthority);
		readAuthority = authorityRepository.save(readAuthority);

		assertNotNull(readAuthority.getId());
		Authority found = authorityRepository.findByName(AuthorityName.READ_AUTHORITY);
		foundUser = userRepository.findAppUserByUserDataEmail(appUser.getEmail());
		assertEquals(found, readAuthority);
		assertEquals(foundUser.getAuthorities().size(), 1);
	}
	
	@Test
	public void testSaveAuthorityWithNullAuthorityNameShouldThrowException() {
		authority.setName(null);
		assertThrows(ConstraintViolationException.class, () -> {
			authorityRepository.saveAllAndFlush(Collections.singletonList(authority));
		});
	}
	
	@Test
	public void testSaveAuthorityWithDuplicateAuthorityNameShouldThrowException() {
		Authority createAuthority = new Authority();
		createAuthority.setName(authority.getName());
		assertThrows(DataIntegrityViolationException.class, () -> {
			authorityRepository.saveAllAndFlush(Collections.singletonList(createAuthority));
		});
	}
}
