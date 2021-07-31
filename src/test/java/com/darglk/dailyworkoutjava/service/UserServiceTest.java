package com.darglk.dailyworkoutjava.service;

import com.darglk.dailyworkoutjava.domain.user.dto.UserDTO;
import com.darglk.dailyworkoutjava.domain.user.dto.UserDataDTO;
import com.darglk.dailyworkoutjava.domain.user.entity.*;
import com.darglk.dailyworkoutjava.domain.user.entity.embedded.UserData;
import com.darglk.dailyworkoutjava.domain.user.repository.*;
import com.darglk.dailyworkoutjava.domain.user.request.ChangePasswordRequestModel;
import com.darglk.dailyworkoutjava.domain.user.request.UserDataRequestModel;
import com.darglk.dailyworkoutjava.domain.user.request.admin.PasswordRequestModel;
import com.darglk.dailyworkoutjava.domain.user.request.admin.UserDataExtendedModel;
import com.darglk.dailyworkoutjava.domain.user.request.admin.UserModelRequest;
import com.darglk.dailyworkoutjava.domain.user.service.UserServiceImpl;
import com.darglk.dailyworkoutjava.exception.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2RefreshToken;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import java.time.Instant;
import java.time.Period;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(SpringExtension.class)
public class UserServiceTest {
	@Mock
	private UserRepository userRepository;
	
	@Mock
	private RoleRepository roleRepository;
	
	@Mock
	private PasswordEncoder passwordEncoder;
	
	@Mock
	private AccountActivationTokenRepository accountActivationTokenRepository;
	
	@Mock
	private JavaMailSender mailSender;
	
	@Mock
	private PasswordTokenRepository passwordTokenRepository;
	
	@Mock
	private AuthorityRepository authorityRepository;
	
	@Mock
	private AppUser user;
	
	@Mock
	private PasswordResetToken resetToken;
	
	@Mock
	private AccountActivationToken activationToken;
	
	@Mock
	private ChangePasswordRequestModel changePasswordRequestModel;
	
	@Mock
	private PasswordRequestModel passwordRequestModel;
	
	@Mock
	private UserDTO userDTO;
	
	@Mock
	private UserDataDTO userDataDTO;
	
	@Mock
	private Authority readAuthority;
	
	@Mock
	private Role userRole;
	
	@Mock
	private AccountActivationToken accountActivationToken;
	
	@Mock
	private UserData userData;
	
	@InjectMocks
	private UserServiceImpl userService;

	@Mock
	private UserModelRequest userModelRequest;
	
	@Mock
	private UserDataRequestModel userDataRequestModel;
	
	@Mock
	private UserDataExtendedModel userDataExtendedModel;
	
	@Mock
	private JdbcClientDetailsService clientDetailsService;
	
	@Mock
	private ApprovalStore approvalStore;
	
	@Mock
	private TokenStore tokenStore;
	
	@Mock
	private ClientDetails clientDetails;
	
	@Mock
	private OAuth2AccessToken accessToken;

	private String clientId = "client_id";

	@Mock
	private OAuth2RefreshToken refreshToken;

	@BeforeEach
	public void setUp() {
		List<SimpleGrantedAuthority> authorities = new ArrayList<>();
		lenient().when(user.getAllAuthorities()).thenReturn(authorities);
		lenient().when(user.getEmail()).thenReturn("test@test.com");
		lenient().when(user.getPassword()).thenReturn("password");
		lenient().when(user.getEnabled()).thenReturn(true);
		lenient().when(user.getId()).thenReturn("userId");
		lenient().when(user.getUserData()).thenReturn(userData);
		
		lenient().when(userData.getEmail()).thenReturn("test@test.com");
		
		lenient().when(changePasswordRequestModel.getOldPassword()).thenReturn("abcdefgh");
		lenient().when(changePasswordRequestModel.getPasswords()).thenReturn(passwordRequestModel);
		lenient().when(passwordRequestModel.getPassword()).thenReturn("asdf");
		lenient().when(passwordRequestModel.getPasswordConfirmation()).thenReturn("asdf");
		userService.setPasswordEncoder(passwordEncoder);
		
		lenient().when(userDataDTO.getEmail()).thenReturn("test@test.com");
		lenient().when(userDTO.getUserData()).thenReturn(userDataDTO);
		lenient().when(userDTO.getAuthorities()).thenReturn(new HashSet<Authority>());
		lenient().when(userDTO.getRoles()).thenReturn(new HashSet<Role>());
		lenient().when(userDTO.getEnabled()).thenReturn(false);
		lenient().when(userDTO.getLastAccountUpdateDate()).thenReturn(Date.from(Instant.now()));
		lenient().when(userDTO.getPassword()).thenReturn("password");
		
		lenient().when(authorityRepository.findByName(AuthorityName.READ_AUTHORITY)).thenReturn(readAuthority);
		lenient().when(roleRepository.findByName(RoleName.ROLE_USER)).thenReturn(userRole);
		
		lenient().when(accountActivationToken.getUser()).thenReturn(user);
		
		lenient().when(userDataRequestModel.getEmail()).thenReturn("test@test.com");
		
		lenient().when(userModelRequest.getUserData()).thenReturn(userDataRequestModel);
		lenient().when(userModelRequest.getPasswords()).thenReturn(passwordRequestModel);
		lenient().when(userModelRequest.getAuthorityIds()).thenReturn(new HashSet<>());
		lenient().when(userModelRequest.getRoleIds()).thenReturn(new HashSet<>());
		lenient().when(userModelRequest.getEnabled()).thenReturn(false);
		
		lenient().when(userDataExtendedModel.getAuthorityIds()).thenReturn(new HashSet<>());
		lenient().when(userDataExtendedModel.getRoleIds()).thenReturn(new HashSet<>());
		lenient().when(userDataExtendedModel.getEmail()).thenReturn("test@test.com");
		lenient().when(userDataExtendedModel.getEnabled()).thenReturn(true);

		List<ClientDetails> clientDetailsList = Arrays.asList(clientDetails);
		lenient().when(clientDetails.getClientId()).thenReturn(clientId);
		lenient().when(clientDetailsService.listClientDetails()).thenReturn(clientDetailsList);
		lenient().when(tokenStore.findTokensByClientIdAndUserName(Mockito.anyString(), Mockito.anyString())).thenReturn(Collections.emptyList());
		lenient().when(accessToken.getRefreshToken()).thenReturn(refreshToken);
		lenient().when(approvalStore.getApprovals(Mockito.anyString(), Mockito.anyString())).thenReturn(Collections.emptyList());
	}
	
	@Test
	public void testLoadUserByUsernameShouldThrowAnExceptionWhenAppUserIsNotFound() {
		String email = "test@test.com";
		assertThrows(UsernameNotFoundException.class, () -> {
			userService.loadUserByUsername(email);
		});
	}
	
	@Test
	public void testLoadUserByUsernameShouldReturnUserDetailsWhenUserIsFound() {
		String email = "test@test.com";
		when(userRepository.findAppUserByUserDataEmail(email)).thenReturn(user);
		UserDetails userDetails = userService.loadUserByUsername(email);
		
		assertNotNull(userDetails);
		verify(userRepository, times(1)).findAppUserByUserDataEmail(email);
		verify(user, times(1)).getAllAuthorities();
		verify(user, times(1)).getEmail();
		verify(user, times(1)).getPassword();
		verify(user, times(1)).getEnabled();
	}
	
	@Test
	public void testFindUserByEmail() {
		String email = "test@test.com";
		when(userRepository.findAppUserByUserDataEmail(email)).thenReturn(user);
		AppUser found = userService.findUserByEmail(email);
		assertNotNull(found);
	}
	
	@Test
	public void testUpdatePasswordShouldThrowExceptionWhenPasswordEncoderDoesNotMatchOldPassword() {
		String invalidOldPassword = "aaaaaaaaa";
		when(changePasswordRequestModel.getOldPassword()).thenReturn(invalidOldPassword);
		when(passwordEncoder.matches(invalidOldPassword, user.getPassword())).thenReturn(false);
		assertThrows(InvalidOldPasswordException.class, () -> {
			userService.updatePassword(user, changePasswordRequestModel);
		});
	}
	
	@Test
	public void testUpdatePasswordShouldUpdatePasswordWhenPasswordsMatch() {
		String hashedPassword = "hashedpasssword";
		
		when(passwordEncoder.matches(changePasswordRequestModel.getOldPassword(), user.getPassword())).thenReturn(true);
		when(passwordEncoder.encode(changePasswordRequestModel.getPasswords().getPassword())).thenReturn(hashedPassword);
		
		userService.updatePassword(user, changePasswordRequestModel);
		verify(user, times(1)).setPassword(hashedPassword);
		verify(userRepository, times(1)).save(user);
	}
	
	@Test
	public void testCreateStandardUserShouldThrowExceptionWhenUserWithGivenEmailExists() {
		when(userRepository.findAppUserByUserDataEmail(userDTO.getUserData().getEmail())).thenReturn(user);
		assertThrows(UsernameAlreadyExistsException.class, () -> {
			userService.createStandardUser(userDTO);
		});
	}
	
	@Test
	public void testCreateStandardUserShouldCreateUserWhenEmailDoesNotExist() {
		String hashedPassword = "hashedpasssword";
		when(passwordEncoder.encode(userDTO.getPassword())).thenReturn(hashedPassword);
		when(userRepository.save(Mockito.any())).thenReturn(user);
		
		userService.createStandardUser(userDTO);
		
		verify(authorityRepository, times(1)).findByName(AuthorityName.READ_AUTHORITY);
		verify(roleRepository, times(1)).findByName(RoleName.ROLE_USER);
		verify(passwordEncoder, times(1)).encode(userDTO.getPassword());
		verify(userRepository, times(1)).save(Mockito.any());
		verify(roleRepository, times(1)).save(Mockito.any());
		verify(authorityRepository, times(1)).save(Mockito.any());
		//verify(mailSender, times(1)).send(Mockito.any(SimpleMailMessage.class));
		verify(accountActivationTokenRepository, times(1)).save(Mockito.any());
	}
	
	@Test
	public void testActivateUserAccountShouldThrowInvalidActivationTokenExceptionWhenTokenIsNotFound() {
		String token = "invalidtoken";
		String userId = "userId";
		assertThrows(InvalidActivationTokenException.class, () -> {
			userService.activateUserAccount(userId, token);
		});
		verify(accountActivationTokenRepository, times(1)).findByToken(token);
	}
	
	@Test
	public void testActivateUserAccountShouldThrowInvalidActivationTokenExceptionWhenTokenUserIdIsDifferent() {
		String token = "invalidtoken";
		String userId = "userId1";
		when(accountActivationTokenRepository.findByToken(token)).thenReturn(accountActivationToken);
		assertThrows(InvalidActivationTokenException.class, () -> {
			userService.activateUserAccount(userId, token);
		});
		verify(accountActivationTokenRepository, times(1)).findByToken(token);
		verify(accountActivationToken, times(1)).getUser();
	}
	
	@Test
	public void testActivateUserAccountShouldDeleteTokenAndUpdateUserAccount() {
		String token = "invalidtoken";
		String userId = "userId";
		when(accountActivationTokenRepository.findByToken(token)).thenReturn(accountActivationToken);

		userService.activateUserAccount(userId, token);

		verify(accountActivationTokenRepository, times(1)).findByToken(token);
		verify(accountActivationToken, times(1)).getUser();
		verify(accountActivationTokenRepository, times(1)).delete(accountActivationToken);
		verify(userRepository, times(1)).save(user);
	}
	
	@Test
	public void testCreatePasswordResetTokenShouldThrowExceptionWhenUserWithGivenEmailIsNotFound() {
		String email = "test@test.com";
		assertThrows(UsernameNotFoundException.class, () -> {
			userService.createPasswordResetToken(email);
		});
		verify(userRepository, times(1)).findAppUserByUserDataEmail(email);
	}
	
	@Test
	public void testCreatePasswordResetTokenShouldDeleteExistingTokenAndCreateNewOne() {
		String email = "test@test.com";
		when(userRepository.findAppUserByUserDataEmail(email)).thenReturn(user);
		when(passwordTokenRepository.findByUser(user)).thenReturn(resetToken);
		when(tokenStore.findTokensByClientIdAndUserName(clientId, user.getEmail())).thenReturn(Arrays.asList(accessToken));
		
		userService.createPasswordResetToken(email);
		
		verify(userRepository, times(1)).findAppUserByUserDataEmail(email);
		verify(passwordTokenRepository, times(1)).findByUser(user);
		verify(passwordTokenRepository, times(1)).delete(resetToken);
		verify(clientDetailsService, times(1)).listClientDetails();
		verify(clientDetails, times(2)).getClientId();
		verify(tokenStore, times(1)).findTokensByClientIdAndUserName(clientId, user.getEmail());
		verify(accessToken, times(1)).getRefreshToken();
		verify(tokenStore, times(1)).removeRefreshToken(refreshToken);
		verify(tokenStore, times(1)).removeAccessToken(accessToken);
		verify(passwordTokenRepository, times(1)).save(Mockito.any());
		verify(userRepository, times(1)).save(user);
//		verify(mailSender, times(1)).send(Mockito.any(SimpleMailMessage.class));
		verify(approvalStore, times(1)).getApprovals(Mockito.anyString(), Mockito.anyString());
		verify(approvalStore, times(1)).revokeApprovals(Mockito.any());
	}
	
	@Test
	public void testCreatePasswordResetTokenShouldNotDeleteTokenAndCreateNewOne() {
		String email = "test@test.com";
		when(userRepository.findAppUserByUserDataEmail(email)).thenReturn(user);
		userService.createPasswordResetToken(email);
		
		verify(userRepository, times(1)).findAppUserByUserDataEmail(email);
		verify(passwordTokenRepository, times(1)).findByUser(user);
		verify(passwordTokenRepository, times(0)).delete(resetToken);
		verify(passwordTokenRepository, times(1)).save(Mockito.any());
		verify(userRepository, times(1)).save(user);
		//verify(mailSender, times(1)).send(Mockito.any(SimpleMailMessage.class));
	}
	
	@Test
	public void testChangeForgottenPasswordShouldThrowExceptionWhenPasswordTokenIsNotFound() {
		String token = "token";
		String userId = "userId";
		assertThrows(InvalidPasswordResetTokenException.class, () -> {
			userService.changeForgottenPassword(passwordRequestModel, userId, token);
		});
	}
	
	@Test
	public void testChangeForgottenPasswordShouldThrowExceptionWhenUserIdIsDifferent() {
		String token = "token";
		String userId = "userId1";
		when(passwordTokenRepository.findByToken(token)).thenReturn(resetToken);
		when(resetToken.getUser()).thenReturn(user);
		assertThrows(InvalidPasswordResetTokenException.class, () -> {
			userService.changeForgottenPassword(passwordRequestModel, userId, token);
		});
	}
	
	@Test
	public void testChangeForgottenPasswordShouldThrowExceptionWhenTokenIsExpired() {
		String token = "token";
		String userId = "userId";
		when(passwordTokenRepository.findByToken(token)).thenReturn(resetToken);
		when(resetToken.getUser()).thenReturn(user);
		when(resetToken.getExpiryDate()).thenReturn(Date.from(Instant.now().minus(Period.ofDays(2))));
		assertThrows(PasswordResetTokenExpiredException.class, () -> {
			userService.changeForgottenPassword(passwordRequestModel, userId, token);
		});
		verify(passwordTokenRepository, times(1)).delete(resetToken);
	}
	
	@Test
	public void testChangeForgottenPasswordShouldUpdateUserAndDeleteToken() {
		String token = "token";
		String userId = "userId";
		when(passwordTokenRepository.findByToken(token)).thenReturn(resetToken);
		when(resetToken.getUser()).thenReturn(user);
		when(resetToken.getExpiryDate()).thenReturn(Date.from(Instant.now().plus(Period.ofDays(2))));
		when(passwordEncoder.encode(Mockito.anyString())).thenReturn("hashed");
		userService.changeForgottenPassword(passwordRequestModel, userId, token);
		
		verify(passwordTokenRepository, times(1)).delete(resetToken);
		verify(userRepository, times(1)).save(user);
		verify(user, times(1)).setPassword(Mockito.anyString());
		verify(passwordEncoder, times(1)).encode(Mockito.anyString());
	}
	
	@Test
	public void testUpdateUserDataShouldThrowExceptioniWhenUserEmailAlreadyExists() {
		String email = "test1@test.com";
		when(userDataDTO.getEmail()).thenReturn(email);
		when(userRepository.findAppUserByUserDataEmail(email)).thenReturn(user);

		assertThrows(UsernameAlreadyExistsException.class, () -> {
			userService.updateUserData(userDataDTO, email);
		});
		verify(userRepository, times(2)).findAppUserByUserDataEmail(email);
	}
	
	@Test
	public void testUpdateUserDataShouldSucceed() {
		String email = "test1@test.com";
		when(userRepository.findAppUserByUserDataEmail(email)).thenReturn(user);
		when(userRepository.save(Mockito.any())).thenReturn(user);
		AppUser updatedUser = userService.updateUserData(userDataDTO, email);

		assertNotNull(updatedUser);
		verify(userRepository, times(1)).findAppUserByUserDataEmail(email);
		verify(userRepository, times(1)).save(Mockito.any());
	}
	
	@Test
	public void testCreateUserShouldThrowExceptionWhenUserEmailExists() {
		String email = "test@test.com";
		when(userRepository.findAppUserByUserDataEmail(email)).thenReturn(user);
		assertThrows(UsernameAlreadyExistsException.class, () -> {
			userService.createUser(userModelRequest);
		});
		verify(userRepository, times(1)).findAppUserByUserDataEmail(email);
	}
	
	@Test
	public void testCreateUserShouldSucceedWhenAllDataIsCorrect() {
		String email = "test@test.com";
		when(authorityRepository.findAllById(userModelRequest.getAuthorityIds())).thenReturn(new ArrayList<>());
		when(roleRepository.findAllById(userModelRequest.getRoleIds())).thenReturn(new ArrayList<>());
		when(userRepository.save(Mockito.any())).thenReturn(user);
		
		UserDTO created = userService.createUser(userModelRequest);
		
		assertNotNull(created);
		verify(authorityRepository, times(1)).findAllById(userModelRequest.getAuthorityIds());
		verify(roleRepository, times(1)).findAllById(userModelRequest.getRoleIds());
		verify(userRepository, times(1)).findAppUserByUserDataEmail(email);
		verify(userRepository, times(1)).save(Mockito.any());
	}
	
	@Test
	public void testUpdateUserShouldThrowExceptionWhenUserIdIsNotFound() {
		String userId = "userId";
		when(userRepository.findById(userId)).thenReturn(Optional.empty());
		assertThrows(UsernameNotFoundException.class, () -> {
			userService.updateUser(userDataExtendedModel, userId);
		});
		verify(userRepository, times(1)).findById(userId);
	}
	
	@Test
	public void testUpdateUserShouldThrowExceptionWhenUserEmailAlreadyExists() {
		String email = "test1@test.com";
		String userId = "userId";
		when(userDataExtendedModel.getEmail()).thenReturn(email);
		when(userRepository.findById(userId)).thenReturn(Optional.of(user));
		when(userRepository.findAppUserByUserDataEmail(email)).thenReturn(user);
		assertThrows(UsernameAlreadyExistsException.class, () -> {
			userService.updateUser(userDataExtendedModel, userId);
		});
		verify(userRepository, times(1)).findById(userId);
	}
	
	@Test
	public void testUpdateUserShouldSucceedWhenAllDataIsCorrect() {		
		String userId = "userId";
		when(userRepository.findById(userId)).thenReturn(Optional.of(user));
		when(authorityRepository.findAllById(userDataExtendedModel.getAuthorityIds())).thenReturn(new ArrayList<>());
		when(roleRepository.findAllById(userDataExtendedModel.getRoleIds())).thenReturn(new ArrayList<>());
		when(userRepository.save(Mockito.any())).thenReturn(user);
		UserDTO updatedUser = userService.updateUser(userDataExtendedModel, userId);
		
		assertNotNull(updatedUser);
		verify(userRepository, times(1)).findById(userId);
		verify(authorityRepository, times(1)).findAllById(userDataExtendedModel.getAuthorityIds());
		verify(roleRepository, times(1)).findAllById(userDataExtendedModel.getRoleIds());
		verify(userRepository, times(1)).save(Mockito.any());
	}
	
	@Test
	public void testFindUserByIdShouldThrowExceptionWhenIdIsNotFound() {
		String userId = "userId";
		assertThrows(UsernameNotFoundException.class, () -> {
			userService.findUserById(userId);
		});
		verify(userRepository, times(1)).findById(userId);
	}
	
	@Test
	public void testFindUserByIdShouldReturnUserDataWhenIdExists() {
		String userId = "userId";
		when(userRepository.findById(userId)).thenReturn(Optional.of(user));
		
		UserDTO foundUser = userService.findUserById(userId);
		assertNotNull(foundUser);
		verify(userRepository, times(1)).findById(userId);
	}
	
	@Test
	public void testGetUserShouldReturnPagedUsersByEmailWhenSearchByStringIsIncorrect() {
		String searchBy = "incorrect";
		String search = "test";
		Pageable pageable = PageRequest.of(0, 2);
		Page<AppUser> pagedAppUsers = new PageImpl<>(Arrays.asList(user, user));
		when(userRepository.findByUserDataEmail(search, pageable)).thenReturn(pagedAppUsers);
		
		Page<UserDTO> content = userService.getUsers(search, searchBy, pageable);
		
		assertEquals(content.getContent().size(), 2);
		verify(userRepository, times(1)).findByUserDataEmail(search, pageable);
	}
	
	@Test
	public void testDeleteUserShouldThrowExceptionWhenUserIdDoesNotExist() {
		String userId = "userId";
		when(userRepository.findById(userId)).thenReturn(Optional.empty());
		
		assertThrows(UsernameNotFoundException.class, () -> {
			userService.deleteUser(userId);
		});
		
		verify(userRepository, times(1)).findById(userId);
	}
	
	@Test
	public void testDeleteUserShouldSucceedWhenUserIdExists() {
		String userId = "userId";
		when(userRepository.findById(userId)).thenReturn(Optional.of(user));
		
		userService.deleteUser(userId);
				
		verify(userRepository, times(1)).findById(userId);
		verify(userRepository, times(1)).delete(user);
	}
	
	@Test
	public void testDeleteUserByName() {
		String email = "test@test.com";
		when(userRepository.findById(email)).thenReturn(Optional.of(user));
		
		userService.deleteUser(email);
		
		verify(userRepository, times(1)).findById(email);
		verify(userRepository, times(1)).delete(user);
	}
	
	@Test
	public void testUpdateUserPasswordShouldThrowExceptionWhenUserIdIsNotFound() {
		String userId = "userId";
		when(userRepository.findById(userId)).thenReturn(Optional.empty());
		assertThrows(UsernameNotFoundException.class, () -> {
			userService.updateUserPassword(passwordRequestModel, userId);
		});
		verify(userRepository, times(1)).findById(userId);
	}
	
	@Test
	public void testUpdateUserPasswordShouldSucceedWhenAllDataIsCorrect() {
		String userId = "userId";
		when(userRepository.findById(userId)).thenReturn(Optional.of(user));
		when(userRepository.save(Mockito.any())).thenReturn(user);
		UserDTO updatedUser = userService.updateUserPassword(passwordRequestModel, userId);
		
		assertNotNull(updatedUser);
		verify(userRepository, times(1)).findById(userId);
		verify(userRepository, times(1)).save(Mockito.any());
	}
}
