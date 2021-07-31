package com.darglk.dailyworkoutjava.repository;

import com.darglk.dailyworkoutjava.domain.user.entity.AppUser;
import com.darglk.dailyworkoutjava.domain.user.entity.Role;
import com.darglk.dailyworkoutjava.domain.user.entity.RoleName;
import com.darglk.dailyworkoutjava.domain.user.repository.RoleRepository;
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
import java.util.Date;
import java.util.HashSet;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(SpringExtension.class)
@DataJpaTest
@AutoConfigureTestDatabase(connection = EmbeddedDatabaseConnection.H2)
@TestPropertySource(locations = "classpath:application-repository-test.properties")
@DirtiesContext(classMode = ClassMode.AFTER_EACH_TEST_METHOD)
public class RoleRepositoryTest {

	@Autowired
	private RoleRepository roleRepository;
	
	private Role role;

	private AppUser appUser;

	@Autowired
	private UserRepository userRepository;
	
	@BeforeEach
	public void setUp() {
		role = new Role();
		role.setName(RoleName.ROLE_ADMIN);
		role = roleRepository.save(role);
		
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
	public void testSaveRole() {
		Role roleUser = new Role();
		AppUser foundUser = userRepository.findAppUserByUserDataEmail(appUser.getEmail());
		roleUser.setName(RoleName.ROLE_USER);
		
		roleUser = roleRepository.save(roleUser);
		roleUser.getUsers().add(foundUser);
		roleUser.getUsers().add(foundUser);
		foundUser.getRoles().add(roleUser);
		foundUser.getRoles().add(roleUser);
		roleUser = roleRepository.save(roleUser);

		assertNotNull(roleUser.getId());
		Role found = roleRepository.findByName(RoleName.ROLE_USER);
		foundUser = userRepository.findAppUserByUserDataEmail(appUser.getEmail());
		assertEquals(found, roleUser);
		assertEquals(foundUser.getRoles().size(), 1);
	}
	
	@Test
	public void testSaveRoleWithNullRoleNameShouldThrowException() {
		role.setName(null);
		assertThrows(ConstraintViolationException.class, () -> {
			roleRepository.saveAndFlush(role);
		});
	}
	
	@Test
	public void testSaveRoleWithDuplicateRoleNameShouldThrowException() {
		Role createRole = new Role();
		createRole.setName(role.getName());
		assertThrows(DataIntegrityViolationException.class, () -> {
			roleRepository.saveAndFlush(createRole);
		});
	}
}
