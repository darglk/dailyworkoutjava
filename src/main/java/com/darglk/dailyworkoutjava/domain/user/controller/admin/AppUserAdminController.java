package com.darglk.dailyworkoutjava.domain.user.controller.admin;


import com.darglk.dailyworkoutjava.domain.user.dto.UserDTO;
import com.darglk.dailyworkoutjava.domain.user.entity.AppUser;
import com.darglk.dailyworkoutjava.domain.user.request.admin.PasswordRequestModel;
import com.darglk.dailyworkoutjava.domain.user.request.admin.UserDataExtendedModel;
import com.darglk.dailyworkoutjava.domain.user.request.admin.UserModelRequest;
import com.darglk.dailyworkoutjava.domain.user.response.admin.UserModelResponse;
import com.darglk.dailyworkoutjava.domain.user.service.UserService;
import com.darglk.dailyworkoutjava.utils.Utils;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.*;

import javax.validation.Valid;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/admin/users")
public class AppUserAdminController {

	@Value("${config.pagination.default_page_offset}")
	private Integer PER_PAGE;

	private final UserService userService;

	private final ModelMapper mapper = new ModelMapper();

	public AppUserAdminController(UserService userService) {
		super();
		this.userService = userService;
	}

	@RequestMapping(value = "/create", method = RequestMethod.POST)
	public ResponseEntity<UserModelResponse> createUser(@Valid @RequestBody UserModelRequest model, Errors errors) {
		Utils.checkValidationErrors(errors);
		UserDTO created = userService.createUser(model);
		UserModelResponse response = mapper.map(created, UserModelResponse.class);
		return ResponseEntity.ok(response);
	}

	@RequestMapping(value = "/update/{userId}", method = RequestMethod.PUT)
	public ResponseEntity<UserModelResponse> updateUser(@Valid @RequestBody UserDataExtendedModel model,
			Errors errors, @PathVariable(name = "userId", required = true) String userId) {
		Utils.checkValidationErrors(errors);
		UserDTO updated = userService.updateUser(model, userId);
		UserModelResponse response = mapper.map(updated, UserModelResponse.class);
		return ResponseEntity.ok(response);
	}

	@RequestMapping(value = "/update_password/{userId}", method = RequestMethod.PUT)
	public ResponseEntity<UserModelResponse> updateUserPassword(@Valid @RequestBody PasswordRequestModel model,
			Errors errors, @PathVariable(name = "userId", required = true) String userId) {
		Utils.checkValidationErrors(errors);
		UserDTO updated = userService.updateUserPassword(model, userId);
		UserModelResponse response = mapper.map(updated, UserModelResponse.class);
		return ResponseEntity.ok(response);
	}

	@RequestMapping(value = "/show/{userId}", method = RequestMethod.GET)
	public ResponseEntity<UserModelResponse> showUser(@PathVariable("userId") String userId) {
		UserDTO user = userService.findUserById(userId);
		UserModelResponse response = mapper.map(user, UserModelResponse.class);
		return ResponseEntity.ok(response);
	}

	@RequestMapping(value = { "/list/{pageNum}", "/list" }, method = RequestMethod.GET)
	public Page<UserModelResponse> showUsers(@PathVariable(value = "pageNum", required = false) Integer pageNumber,
			@RequestParam(value = "per_page", required = false) String perPage,
			@RequestParam(value = "search", required = false, defaultValue = "") String searchString,
			@RequestParam(value = "searchBy", required = false, defaultValue = "email") String searchBy) {
		if (pageNumber == null) {
			pageNumber = 0;
		}
		int pageOffset = calculatePageOffset(perPage);
		Pageable pageable = PageRequest.of(pageNumber, pageOffset);
		Page<UserDTO> users = userService.getUsers(searchString, searchBy, pageable);
		List<UserModelResponse> usersContent = users.get().map(userDTO -> mapper.map(userDTO, UserModelResponse.class))
				.collect(Collectors.toList());
		return new PageImpl<>(usersContent, pageable, users.getTotalElements());
	}

	@RequestMapping(value = "/delete/{userId}", method = RequestMethod.DELETE)
	public ResponseEntity<?> deleteUser(@PathVariable("userId") String userId) {
		userService.deleteUser(userId);
		return ResponseEntity.noContent().build();
	}
	
	@RequestMapping(value = "/sign_user_out/{userId}", method = RequestMethod.POST)
	public ResponseEntity<?> signUserOut(@PathVariable("userId") String userId) {
		Optional<AppUser> userOpt = userService.findById(userId);
		if (userOpt.isPresent()) {
			userService.signOutUser(userOpt.get());
			return ResponseEntity.noContent().build();
		}
		return ResponseEntity.notFound().build();
	}

	private int calculatePageOffset(String perPage) {
		int defaultPageOffset;
		try {
			defaultPageOffset = Integer.parseInt(perPage);
			if (defaultPageOffset <= 0) {
				defaultPageOffset = PER_PAGE;
			}
		} catch (NumberFormatException e) {
			defaultPageOffset = PER_PAGE;
		}
		return defaultPageOffset;
	}
}
