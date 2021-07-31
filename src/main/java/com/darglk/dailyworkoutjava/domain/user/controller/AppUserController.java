package com.darglk.dailyworkoutjava.domain.user.controller;

import com.darglk.dailyworkoutjava.domain.user.dto.UserDTO;
import com.darglk.dailyworkoutjava.domain.user.dto.UserDataDTO;
import com.darglk.dailyworkoutjava.domain.user.entity.AppUser;
import com.darglk.dailyworkoutjava.domain.user.request.ChangePasswordRequestModel;
import com.darglk.dailyworkoutjava.domain.user.request.ForgotPasswordRequestModel;
import com.darglk.dailyworkoutjava.domain.user.request.UserDataRequestModel;
import com.darglk.dailyworkoutjava.domain.user.request.UserRegistrationRequestModel;
import com.darglk.dailyworkoutjava.domain.user.request.admin.PasswordRequestModel;
import com.darglk.dailyworkoutjava.domain.user.response.ResponseModel;
import com.darglk.dailyworkoutjava.domain.user.response.UserRegistrationModelResponse;
import com.darglk.dailyworkoutjava.domain.user.service.UserService;
import com.darglk.dailyworkoutjava.utils.ResponseMessages;
import com.darglk.dailyworkoutjava.utils.Utils;
import org.modelmapper.ModelMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;

@RestController
@RequestMapping("/api/users")
public class AppUserController {

	private UserService userService;

	public AppUserController(UserService userService) {
		this.userService = userService;
	}

	@RequestMapping(value = "/change_password", method = RequestMethod.PUT)
	public ResponseEntity<OAuth2AccessToken> changePassword(@Valid @RequestBody ChangePasswordRequestModel model, Errors errors,
															HttpServletRequest request, HttpServletResponse response) {
		Utils.checkValidationErrors(errors);
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		AppUser user = userService.findUserByEmail(authentication.getName());
		userService.updatePassword(user, model);

		OAuth2AccessToken accessToken = userService.removeAccessTokens(request.getHeader("Authorization"));
		
		accessToken = userService.requestNewAccessToken(request, user, accessToken);
		return ResponseEntity.ok().body(accessToken);
	}

	@RequestMapping(value = "/sign_up", method = RequestMethod.POST)
	public ResponseEntity<UserRegistrationModelResponse> signUp(
			@Valid @RequestBody UserRegistrationRequestModel newUser, Errors errors) {
		Utils.checkValidationErrors(errors);
		ModelMapper mapper = new ModelMapper();
		UserDTO userDTO = mapper.map(newUser, UserDTO.class);
		userDTO.setPassword(newUser.getPasswords().getPassword());
		UserDTO createdUser = userService.createStandardUser(userDTO);
		UserRegistrationModelResponse response = mapper.map(createdUser, UserRegistrationModelResponse.class);
		return ResponseEntity.ok(response);
	}

	@RequestMapping(value = "/activate_account", method = RequestMethod.GET)
	public ResponseEntity<?> activateAccount(@RequestParam("userId") String userId, @RequestParam("token") String token) {
		userService.activateUserAccount(userId, token);
		return ResponseEntity.ok().build();
	}

	@RequestMapping(value = "/forgot_password", method = RequestMethod.POST)
	public ResponseEntity<ResponseModel> forgotPassword(@RequestBody @Valid ForgotPasswordRequestModel model,
														Errors errors) {
		Utils.checkValidationErrors(errors);
		userService.createPasswordResetToken(model.getEmail());
		return ResponseEntity.ok(new ResponseModel(ResponseMessages.PASSWORD_TOKEN_CREATED_MESSAGE));
	}

	@RequestMapping(value = "/reset_password", method = RequestMethod.POST)
	public ResponseEntity<ResponseModel> resetPassword(@RequestBody @Valid PasswordRequestModel model,
			Errors errors, @RequestParam("userId") String userId, @RequestParam("token") String token) {
		Utils.checkValidationErrors(errors);
		userService.changeForgottenPassword(model, userId, token);
		return ResponseEntity.ok(new ResponseModel(ResponseMessages.PASSWORD_HAS_BEEN_CHANGED_MESSAGE));
	}

	@RequestMapping(value = "/update", method = RequestMethod.PUT)
	public ResponseEntity<OAuth2AccessToken> updateAccountData(@RequestBody @Valid UserDataRequestModel model,
			Errors errors, HttpServletRequest request, HttpServletResponse response) {
		Utils.checkValidationErrors(errors);
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		ModelMapper mapper = new ModelMapper();
		UserDataDTO userDataDTO = mapper.map(model, UserDataDTO.class);
		AppUser updatedAppUser = userService.updateUserData(userDataDTO, authentication.getName());

		OAuth2AccessToken accessToken = userService.removeAccessTokens(request.getHeader("Authorization"));
		accessToken = userService.requestNewAccessToken(request, updatedAppUser, accessToken);

		return ResponseEntity.ok().body(accessToken);
	}

	@RequestMapping(value = "/delete", method = RequestMethod.DELETE)
	public ResponseEntity<?> deleteAccount(HttpServletRequest request) {
		String username = SecurityContextHolder.getContext().getAuthentication().getName();
		AppUser user = userService.findUserByEmail(username);
		userService.deleteUser(user.getId());
		userService.removeAccessTokens(request.getHeader("Authorization"));
		SecurityContextHolder.clearContext();
		
		return ResponseEntity.noContent().build();
	}

	@RequestMapping(value = "/me", method = RequestMethod.GET)
	public ResponseEntity<?> aboutMe() {
		String username = SecurityContextHolder.getContext().getAuthentication().getName();
		return ResponseEntity.ok(username);
	}
}
