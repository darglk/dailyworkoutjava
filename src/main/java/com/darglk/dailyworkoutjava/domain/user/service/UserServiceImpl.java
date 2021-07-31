package com.darglk.dailyworkoutjava.domain.user.service;

import com.darglk.dailyworkoutjava.domain.user.dto.UserDTO;
import com.darglk.dailyworkoutjava.domain.user.dto.UserDataDTO;
import com.darglk.dailyworkoutjava.domain.user.entity.*;
import com.darglk.dailyworkoutjava.domain.user.entity.embedded.UserData;
import com.darglk.dailyworkoutjava.domain.user.repository.*;
import com.darglk.dailyworkoutjava.domain.user.request.ChangePasswordRequestModel;
import com.darglk.dailyworkoutjava.domain.user.request.admin.PasswordRequestModel;
import com.darglk.dailyworkoutjava.domain.user.request.admin.UserDataExtendedModel;
import com.darglk.dailyworkoutjava.domain.user.request.admin.UserModelRequest;
import com.darglk.dailyworkoutjava.exception.*;
import com.darglk.dailyworkoutjava.utils.MailMessages;
import com.darglk.dailyworkoutjava.utils.Utils;
import com.darglk.dailyworkoutjava.utils.ValidationErrorMessages;
import lombok.extern.slf4j.Slf4j;
import org.modelmapper.ModelMapper;
import org.modelmapper.PropertyMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.context.annotation.Lazy;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.Pageable;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;
import org.springframework.security.oauth2.provider.approval.Approval;
import org.springframework.security.oauth2.provider.approval.ApprovalStore;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.AuthorizationServerTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import javax.transaction.Transactional;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.stream.Collectors;

/**
 * Implementation of methods defined in UserService interface.
 * @author darglk
 *
 */
@Service
@Slf4j
public class UserServiceImpl implements UserService {
	@Autowired
	private UserRepository userRepository;
	@Autowired
	private AuthorityRepository authorityRepository;
	@Autowired
	private RoleRepository roleRepository;
	@Autowired
	private PasswordEncoder passwordEncoder;
	@Autowired
	private AccountActivationTokenRepository accountActivationTokenRepository;
	@Autowired
	private JavaMailSender mailSender;
	@Autowired
	private PasswordTokenRepository passwordTokenRepository;
	@Autowired
	private JdbcClientDetailsService clientDetailsService;
	@Autowired
	private ApprovalStore approvalStore;
	@Autowired
	private TokenStore tokenStore;

	/**
	 * tokenServices - used for managing stored access and refresh tokens.
	 */
	@Autowired
	public AuthorizationServerTokenServices tokenServices;

	@Autowired
	public void setPasswordEncoder(@Lazy PasswordEncoder passwordEncoder) {
		this.passwordEncoder = passwordEncoder;
	}

	@Override
	@Transactional
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		AppUser appUser = userRepository.findAppUserByUserDataEmail(username);

		if (appUser == null) {
			log.info("User with {} was not found", username);
			throw new UsernameNotFoundException(username);
		}
		List<SimpleGrantedAuthority> auths = appUser.getAllAuthorities();
		return new User(appUser.getEmail(), appUser.getPassword(), appUser.getEnabled(), true, true, true, auths);
	}

	@Override
	@Transactional
	public AppUser findUserByEmail(String email) {
		return userRepository.findAppUserByUserDataEmail(email);
	}

	@Override
	@Transactional
	public void updatePassword(AppUser user, ChangePasswordRequestModel model) {
		if (!passwordEncoder.matches(model.getOldPassword(), user.getPassword())) {
			log.info("Attempt to change non matching password failed");
			throw new InvalidOldPasswordException(ValidationErrorMessages.OLD_PASSWORD_DOES_NOT_MATCH);
		}
		String encryptedPassword = passwordEncoder.encode(model.getPasswords().getPassword());
		user.setPassword(encryptedPassword);
		userRepository.save(user);
	}

	@Override
	@Transactional
	public UserDTO createStandardUser(UserDTO userDTO) {
		if (userRepository.findAppUserByUserDataEmail(userDTO.getUserData().getEmail()) != null) {
			log.info("User with {} already exists", userDTO.getUserData().getEmail());
			throw new UsernameAlreadyExistsException(ValidationErrorMessages.USERNAME_EXISTS_MESSAGE);
		}
		ModelMapper mapper = new ModelMapper();
		Authority readAuthority = authorityRepository.findByName(AuthorityName.READ_AUTHORITY);
		Role userRole = roleRepository.findByName(RoleName.ROLE_USER);

		userDTO.setPassword(passwordEncoder.encode(userDTO.getPassword()));
		userDTO.getAuthorities().add(readAuthority);
		userDTO.getRoles().add(userRole);
		userDTO.setEnabled(false);
		userDTO.setLastAccountUpdateDate(Date.from(Instant.now()));

		AppUser newUser = mapper.map(userDTO, AppUser.class);
		newUser.setId(UUID.randomUUID().toString());
		AppUser saved = userRepository.save(newUser);

		readAuthority.getUsers().add(saved);
		userRole.getUsers().add(saved);

		roleRepository.save(userRole);
		authorityRepository.save(readAuthority);

		String token = UUID.randomUUID().toString();
		AccountActivationToken myToken = new AccountActivationToken();
		myToken.setToken(token);
		myToken.setUser(saved);
		
		sendWelcomeMessage(saved);

		accountActivationTokenRepository.save(myToken);
		return mapper.map(saved, UserDTO.class);
	}

	@Override
	@Transactional
	public void activateUserAccount(String userId, String token) {
		AccountActivationToken activationToken = accountActivationTokenRepository.findByToken(token);

		if (activationToken == null) {
			log.info("Activation token {} was not found", token);
			throw new InvalidActivationTokenException(ValidationErrorMessages.INVALID_ACTIVATION_TOKEN_EXCEPTION);
		}
		AppUser appUser = activationToken.getUser();
		if (!appUser.getId().equals(userId)) {
			log.info("User with id: {} was not found", userId);
			throw new InvalidActivationTokenException(ValidationErrorMessages.INVALID_ACTIVATION_TOKEN_EXCEPTION);
		}
		appUser.setEnabled(true);
		accountActivationTokenRepository.delete(activationToken);
		userRepository.save(appUser);
	}

	@Override
	@Transactional
	public void createPasswordResetToken(String email) {
		AppUser found = userRepository.findAppUserByUserDataEmail(email);
		if (found == null) {
			log.info("User with {} was not found", email);
			throw new UsernameNotFoundException(ValidationErrorMessages.USER_NOT_FOUND_MESSAGE);
		}
		PasswordResetToken resetToken = passwordTokenRepository.findByUser(found);
		if (resetToken != null) {
			log.info("Creating password reset token for {}", email);
			passwordTokenRepository.delete(resetToken);
		}
		String token = UUID.randomUUID().toString();
		resetToken = new PasswordResetToken();
		resetToken.setToken(token);
		resetToken.setUser(found);
		resetToken.setExpiryDate(Date.from(Instant.now().plus(Duration.ofDays(1))));
		passwordTokenRepository.save(resetToken);
		userRepository.save(found);
		signOutUser(found);
		sendPasswordResetMessage(found);
	}

	@Override
	@Transactional
	public void changeForgottenPassword(PasswordRequestModel model, String userId, String token) {
		PasswordResetToken passToken = passwordTokenRepository.findByToken(token);
		if ((passToken == null) || (!passToken.getUser().getId().equals(userId))) {
			log.info("Attempt to change password with invalid token {} or user ID {}", token, userId);
			throw new InvalidPasswordResetTokenException(ValidationErrorMessages.INVALID_PASSWORD_RESET_TOKEN_MESSAGE);
		}

		if (isTokenExpired(passToken)) {
			log.info("Token {} is expired", passToken);
			passwordTokenRepository.delete(passToken);
			throw new PasswordResetTokenExpiredException(ValidationErrorMessages.PASSWORD_RESET_TOKEN_EXPIRED_MESSAGE);
		}
		AppUser tokenUser = passToken.getUser();
		tokenUser.setPassword(passwordEncoder.encode(model.getPassword()));
		signOutUser(tokenUser);
		userRepository.save(tokenUser);
		passwordTokenRepository.delete(passToken);
	}

	@Override
	@Transactional
	public AppUser updateUserData(UserDataDTO userDataDTO, String username) {
		AppUser currentUser = userRepository.findAppUserByUserDataEmail(username);
		// if current user has more unique values that need to be checked before update
		// add more checks here
		checkUniquenessOfUserData(userDataDTO, currentUser);
		ModelMapper mapper = new ModelMapper();
		UserData currentUserData = mapper.map(userDataDTO, UserData.class);
		currentUser.setUserData(currentUserData);
		currentUser = userRepository.save(currentUser);
		return currentUser;
	}

	@Override
	@Transactional
	public UserDTO createUser(UserModelRequest model) {
		if (userRepository.findAppUserByUserDataEmail(model.getUserData().getEmail()) != null) {
			log.info("User with {} already exists", model.getUserData().getEmail());
			throw new UsernameAlreadyExistsException(ValidationErrorMessages.USERNAME_EXISTS_MESSAGE);
		}
		return createNewUser(model);
	}
	
	@Override
	@Transactional
	public UserDTO updateUser(UserDataExtendedModel model, String userId) {
		Optional<AppUser> userToUpdateOpt = userRepository.findById(userId);
		// if user has more unique values that need to be checked before update
		// add more checks here
		if (userToUpdateOpt.isEmpty()) {
			log.info("User with {} was not found", userId);
			throw new UsernameNotFoundException(ValidationErrorMessages.USER_NOT_FOUND_MESSAGE);
		}
		AppUser userToUpdate = userToUpdateOpt.get();
		checkUniquenessOfEmail(model.getEmail(), userToUpdate.getEmail());

		signOutUser(userToUpdate);
		List<Authority> authorities = authorityRepository.findAllById(model.getAuthorityIds());
		List<Role> roles = roleRepository.findAllById(model.getRoleIds());
		
		userToUpdate.setAuthorities(authorities.stream().collect(Collectors.toSet()));
		userToUpdate.setRoles(roles.stream().collect(Collectors.toSet()));
		userToUpdate.setEmail(model.getEmail());
		userToUpdate.setEnabled(model.getEnabled());
		
		AppUser updatedUser = userRepository.save(userToUpdate);
		ModelMapper mapper = new ModelMapper();
		return mapper.map(updatedUser, UserDTO.class);
	}

	@Override
	@Transactional
	public UserDTO findUserById(String userId) {
		AppUser found = userRepository.findById(userId).orElseThrow(() -> new UsernameNotFoundException(ValidationErrorMessages.USER_NOT_FOUND_MESSAGE));
		ModelMapper mapper = new ModelMapper();
		return mapper.map(found, UserDTO.class);
	}

	@Override
	@Transactional
	public Page<UserDTO> getUsers(String search, String searchBy, Pageable pageable) {
		FindUserBy findBy = checkFindUserBy(searchBy);
		Page<AppUser> users = null;
		switch (findBy) {
		case EMAIL:
			users = userRepository.findByUserDataEmail(search, pageable);
		break;
		}
		ModelMapper mapper = new ModelMapper();
		List<UserDTO> usersContent = users.get().map(appUser -> mapper.map(appUser, UserDTO.class)).collect(Collectors.toList());
		return new PageImpl<>(usersContent, pageable, users.getTotalElements()); 
	}
	
	@Override
	@Transactional
	public void deleteUser(String userId) {
		Optional<AppUser> found = userRepository.findById(userId);
		if (found.isEmpty()) {
			log.info("User with {} was not found", userId);
			throw new UsernameNotFoundException(ValidationErrorMessages.USER_NOT_FOUND_MESSAGE);
		}
		
		AppUser user = found.get();
		signOutUser(user);
		userRepository.delete(user);
	}
	
	@Override
	@Transactional
	public UserDTO updateUserPassword(PasswordRequestModel model, String userId) {
		Optional<AppUser> foundUser = userRepository.findById(userId);
		if (!foundUser.isPresent()) {
			log.info("User with {} was not found", userId);
			throw new UsernameNotFoundException(ValidationErrorMessages.USER_NOT_FOUND_MESSAGE);
		}
		AppUser user = foundUser.get();
		
		user.setPassword(passwordEncoder.encode(model.getPassword()));
		AppUser updatedUser = userRepository.save(user);
		signOutUser(updatedUser);
		ModelMapper mapper = new ModelMapper();
		return mapper.map(updatedUser, UserDTO.class);
	}
	
	@Override
	public void signOutUser(AppUser user) {
		clientDetailsService.listClientDetails().stream().forEach(clientDetails -> {
			tokenStore.findTokensByClientIdAndUserName(clientDetails.getClientId(), user.getEmail())
					.forEach(accessToken -> {
						Utils.removeTokens(accessToken, tokenStore);
					});
			Collection<Approval> approvals = approvalStore.getApprovals(user.getEmail(), clientDetails.getClientId());
			approvalStore.revokeApprovals(approvals);
		});
	}
	
	@Override
	public OAuth2AccessToken removeAccessTokens(String authorization) {
		OAuth2AccessToken oauthAccessToken = null;
		if (authorization != null && authorization.contains("Bearer")) {
			String tokenId = authorization.substring("Bearer".length() + 1);
			oauthAccessToken = tokenStore.readAccessToken(tokenId);
			if (oauthAccessToken != null) {
				Utils.removeTokens(oauthAccessToken, tokenStore);
			}
		}
		return oauthAccessToken;
	}
	
	@Override
	public OAuth2AccessToken requestNewAccessToken(HttpServletRequest request, AppUser signedIn,
			OAuth2AccessToken accessToken) {
		Map<String, String> authorizationParams = new HashMap<>();
		String clientId = request.getParameter("client_id");

		authorizationParams.put("scope", accessToken.getScope().stream().collect(Collectors.joining(" ")));
		authorizationParams.put("username", signedIn.getEmail());
		authorizationParams.put("client_id", clientId);
		authorizationParams.put("grant", request.getParameter("grant_type"));

		Set<String> responseType = new HashSet<>();

		OAuth2Request authRequest = new OAuth2Request(authorizationParams, clientId, signedIn.getAllAuthorities(), true,
				accessToken.getScope(), null, "", responseType, null);
		User userPrincipal = new User(signedIn.getEmail(), signedIn.getPassword(), signedIn.getAllAuthorities());
		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userPrincipal,
				null, signedIn.getAllAuthorities());
		OAuth2Authentication authenticationRequest = new OAuth2Authentication(authRequest, authenticationToken);
		authenticationRequest.setAuthenticated(true);
		OAuth2AccessToken newToken = tokenServices.createAccessToken(authenticationRequest);
		return newToken;
	}
	
	@Override
	@Transactional
	public Optional<AppUser> findById(String userId) {
		return userRepository.findById(userId);
	}
	
	private void sendWelcomeMessage(AppUser saved) {
		SimpleMailMessage accountActivationTokenMessage = new SimpleMailMessage();
		accountActivationTokenMessage.setSubject(MailMessages.ACCOUNT_ACTIVATION_LINK_SUBJECT);
		accountActivationTokenMessage.setFrom(MailMessages.APP_MAIL_ADDRESS);
		accountActivationTokenMessage.setTo(saved.getEmail());
		accountActivationTokenMessage.setText(MailMessages.WELCOME_MESSAGE);
		log.info("Sending welcome email message to {}", saved.getEmail());
		ExecutorService service = Executors.newSingleThreadExecutor();
		service.execute(() -> mailSender.send(accountActivationTokenMessage));
		service.shutdown();
	}

	private FindUserBy checkFindUserBy(String searchBy) {
		FindUserBy findBy;
		try {
			findBy = FindUserBy.valueOf(searchBy);
		} catch (IllegalArgumentException e) {
			findBy = FindUserBy.EMAIL;
		}
		return findBy;
	}
	
	private UserDTO createNewUser(UserModelRequest model) {
		List<Authority> authorities = authorityRepository.findAllById(model.getAuthorityIds());
		List<Role> roles = roleRepository.findAllById(model.getRoleIds());
		ModelMapper mapper = mapperForUserModelRequestToDTO();
		UserDTO dest = new UserDTO();
		UserDataDTO userDataDto = new UserDataDTO();
		
		userDataDto.setEmail(model.getUserData().getEmail());
		dest.setEnabled(model.getEnabled());
		dest.setUserData(userDataDto);
		dest.setPassword(model.getPasswords().getPassword());
		dest.setAuthorities(new HashSet<>(authorities));
		dest.setRoles(new HashSet<>(roles));
		dest.setLastAccountUpdateDate(Date.from(Instant.now()));
		
		AppUser newUser = mapper.map(dest, AppUser.class);
		newUser.setId(UUID.randomUUID().toString());
		newUser.setPassword(passwordEncoder.encode(dest.getPassword()));
		AppUser created = userRepository.save(newUser);
		return mapper.map(created, UserDTO.class);
	}

	private ModelMapper mapperForUserModelRequestToDTO() {
		ModelMapper mapper = new ModelMapper();
		mapper.getConfiguration().setAmbiguityIgnored(true);
		PropertyMap<UserModelRequest, UserDTO> propertyMap = new PropertyMap<UserModelRequest, UserDTO>() {
			@Override
			protected void configure() {
				skip(destination.getAuthorities());
				skip(destination.getRoles());
			}
		};
		mapper.addMappings(propertyMap);
		return mapper;
	}

	private boolean isTokenExpired(PasswordResetToken passToken) {
		return passToken.getExpiryDate().before(Date.from(Instant.now()));
	}
	
	private void sendPasswordResetMessage(AppUser found) {
		SimpleMailMessage accountActivationTokenMessage = new SimpleMailMessage();
		accountActivationTokenMessage.setSubject(MailMessages.PASSWORD_RESET_LINK_SUBJECT);
		accountActivationTokenMessage.setFrom(MailMessages.APP_MAIL_ADDRESS);
		accountActivationTokenMessage.setTo(found.getEmail());
		accountActivationTokenMessage.setText(MailMessages.RESET_PASSWORD_MESSAGE);

		log.info("Sending password reset token message to {}", found.getUserData().getEmail());
		ExecutorService service = Executors.newSingleThreadExecutor();
		service.execute(() -> mailSender.send(accountActivationTokenMessage));
		service.shutdown();
	}
	
	private void checkUniquenessOfUserData(UserDataDTO userDataDTO, AppUser currentUser) {
		checkUniquenessOfEmail(userDataDTO.getEmail(), currentUser.getEmail());
	}

	private void checkUniquenessOfEmail(String newEmail, String existingEmail) {
		if (!newEmail.equals(existingEmail)) {
			if (userRepository.findAppUserByUserDataEmail(newEmail) != null) {
				log.info("User with {} email already exists", newEmail);
				throw new UsernameAlreadyExistsException(ValidationErrorMessages.USERNAME_EXISTS_MESSAGE);
			}
		}
	}
}