package com.darglk.dailyworkoutjava.repository;

import com.darglk.dailyworkoutjava.domain.user.entity.*;
import com.darglk.dailyworkoutjava.domain.user.entity.embedded.UserData;
import com.darglk.dailyworkoutjava.domain.user.repository.AuthorityRepository;
import com.darglk.dailyworkoutjava.domain.user.repository.RoleRepository;
import com.darglk.dailyworkoutjava.domain.user.repository.UserRepository;
import com.github.javafaker.Faker;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.jdbc.EmbeddedDatabaseConnection;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.annotation.DirtiesContext.ClassMode;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@DataJpaTest
@AutoConfigureTestDatabase(connection = EmbeddedDatabaseConnection.H2)
@TestPropertySource(locations = "classpath:application-repository-test.properties")
@DirtiesContext(classMode = ClassMode.AFTER_EACH_TEST_METHOD)
public class UserRepositoryTest {

	@Autowired
	private UserRepository userRepository;
	
	@Autowired
	private AuthorityRepository authorityRepository;
	
	@Autowired
	private RoleRepository roleRepository;
	
	private AppUser appUser;
	
	private AppUser existingUser;
	
	private Faker faker = new Faker();
	
	@BeforeEach
	public void setUp() {
		Authority authority = new Authority();
		authority.setName(AuthorityName.CREATE_AUTHORITY);
		authorityRepository.save(authority);
		
		Role role = new Role();
		role.setName(RoleName.ROLE_ADMIN);
		roleRepository.save(role);
		
		existingUser = new AppUser();
		existingUser.setAuthorities(Stream.of(authority).collect(Collectors.toSet()));
		existingUser.setRoles(new HashSet<>(Collections.singletonList(role)));
		existingUser.setEmail("existing@user.com");
		existingUser.setEnabled(true);
		existingUser.setLastPasswordResetDate(Date.from(Instant.now()));
		existingUser.setPassword("password");
		existingUser = userRepository.save(existingUser);
		
		appUser = new AppUser();
		appUser.setAuthorities(new HashSet<>());
		appUser.setRoles(new HashSet<>());
		String email = "test@test.com";
		appUser.setEmail(email );
		appUser.setEnabled(true);
		appUser.setLastPasswordResetDate(Date.from(Instant.now()));
		String password = "password";
		appUser.setPassword(password );
	}
	
	@Test
	public void testSaveUserSuccess() {
		AppUser saved = userRepository.save(appUser);
		assertNotNull(saved.getId());
	}
	
	@Test
	public void testSaveUserWithExistingEmailShouldFail() {
		appUser.setEmail(existingUser.getEmail());
		assertThrows(DataIntegrityViolationException.class, () -> {
			userRepository.saveAndFlush(appUser);
		});
	}
	
	@Test
	public void testPaginationOfUsers() {
		int userNum = 10;
		int perPage = 5;
		List<AppUser> users = createUserList(userNum);
		List<AppUser> subListedUsers = users.subList(0, 3);
		int[] expectedContentSize = {3, 0};
		String[][] userEmails = {{ "test@email.com", "abctest@email.com", "asdf@asdf.test" }, {}};
		for (int i = 0; i < userEmails[0].length; i++) {
			AppUser userToChange = subListedUsers.get(i);
			userToChange.setEmail(userEmails[0][i]);
		}
		userRepository.saveAll(users);
		for (int i = 0; i < userNum / perPage; i++) {
			Pageable pageable = PageRequest.of(i, perPage);
			Page<AppUser> result = userRepository.findByUserDataEmail("test", pageable);
			assertEquals(result.getContent().size(), expectedContentSize[i]);
			assertTrue(result.getContent().stream().map(AppUser::getEmail).collect(Collectors.toList()).containsAll(Arrays.asList(userEmails[i])));
		}
	}
	
	@Test
	public void testFindUserByEmail() {
		AppUser found = userRepository.findAppUserByUserDataEmail(existingUser.getEmail());
		assertNotNull(found);
		List<String> authorityStrings = found.getAllAuthoritiesAsStrings();
		assertEquals(authorityStrings.size(), 2);
		assertTrue(authorityStrings.contains(AuthorityName.CREATE_AUTHORITY.name()));
		assertTrue(authorityStrings.contains(RoleName.ROLE_ADMIN.name()));
	}
	
	@Test
	public void testSaveUserWithNullColumnFields() {
		UserData userData = appUser.getUserData();
		appUser.setUserData(null);
		assertThrows(DataIntegrityViolationException.class, () -> {
			userRepository.saveAndFlush(appUser);
		});
		appUser.setUserData(userData);
		appUser.setEnabled(null);
		assertThrows(Exception.class, () -> {
			userRepository.saveAndFlush(appUser);
		});
		
		appUser.setEnabled(true);
		appUser.setPassword(null);
		assertThrows(Exception.class, () -> {
			userRepository.saveAndFlush(appUser);
		});
		
		appUser.setPassword("password");
		appUser.setLastPasswordResetDate(null);
		assertThrows(Exception.class, () -> {
			userRepository.saveAndFlush(appUser);
		});
	}
	
	private List<AppUser> createUserList(int usersNum) {
		return IntStream.range(0, usersNum).mapToObj(i -> {
			AppUser user = new AppUser();
			setUserRequiredFields(user);
			return user;
		}).collect(Collectors.toList());
	}

	private void setUserRequiredFields(AppUser user) {
		user.setEmail(faker.internet().emailAddress());
		user.setAuthorities(new HashSet<>());
		user.setRoles(new HashSet<>());
		user.setEnabled(true);
		user.setLastPasswordResetDate(Date.from(Instant.now()));
		user.setPassword("password");
	}
}
