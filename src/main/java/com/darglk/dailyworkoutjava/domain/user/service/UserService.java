package com.darglk.dailyworkoutjava.domain.user.service;

import com.darglk.dailyworkoutjava.domain.user.dto.UserDTO;
import com.darglk.dailyworkoutjava.domain.user.dto.UserDataDTO;
import com.darglk.dailyworkoutjava.domain.user.entity.AppUser;
import com.darglk.dailyworkoutjava.domain.user.request.ChangePasswordRequestModel;
import com.darglk.dailyworkoutjava.domain.user.request.admin.PasswordRequestModel;
import com.darglk.dailyworkoutjava.domain.user.request.admin.UserDataExtendedModel;
import com.darglk.dailyworkoutjava.domain.user.request.admin.UserModelRequest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

import javax.servlet.http.HttpServletRequest;
import java.util.Optional;

/**
 * Interface for business logic for AppUser model.
 * 
 * @author darglk
 *
 */
public interface UserService extends UserDetailsService {
	/**
	 * Method used for retrieving user from DB by his email address.
	 * 
	 * @param email - user email address.
	 * @return user which is registered in DB with email address passed in argument.
	 */
	AppUser findUserByEmail(String email);

	/**
	 * Method used for updating user password.
	 * 
	 * @param user  - user which password should be changed.
	 * @param model - request model containing new password.
	 */
	void updatePassword(AppUser user, ChangePasswordRequestModel model);

	/**
	 * Method used for creating user with ROLE_USER. Used in /api/users/sign_up
	 * endpoint.
	 * 
	 * @param userDTO - data transfer object containing new user data.
	 * @return - data transfer object containing stored values of new user.
	 */
	UserDTO createStandardUser(UserDTO userDTO);

	/**
	 * Method used for setting enabled field in DB for given userId.
	 * 
	 * @param userId - ID of user in DB whos account should be activated by given
	 *               token.
	 * @param token  - account activation token passed in query string in
	 *               /api/users/activate_account endpoint.
	 */
	void activateUserAccount(String userId, String token);

	/**
	 * Method used for creating password reset token when user forgots his password.
	 * 
	 * @param email - email of user who has forgot his password.
	 */
	void createPasswordResetToken(String email);

	/**
	 * Method used for changing users forgotten password
	 * 
	 * @param model  - new password for user who tries to change forgotten password.
	 * @param userId - id of user who tries to change forgotten password.
	 * @param token  - one-time password reset token used to authorize user.
	 */
	void changeForgottenPassword(PasswordRequestModel model, String userId, String token);

	/**
	 * Method used for updating user account data.
	 * 
	 * @param userDataDTO - data transfer object containing new user account data.
	 * @param username    - current logged in user name.
	 * @return - data transfer object containing updated user account data.
	 */
	AppUser updateUserData(UserDataDTO userDataDTO, String username);

	/**
	 * Method used for creating user account by admin.
	 * 
	 * @param model - new user account data.
	 * @return - data transfer object containing created user data.
	 */
	UserDTO createUser(UserModelRequest model);

	/**
	 * Method used for updating user account by admin.
	 * 
	 * @param model - user account data.
	 * @param userId - user id in db.
	 * @return - data transfer object containing updated user data.
	 */
	UserDTO updateUser(UserDataExtendedModel model, String userId);

	/**
	 * Method used for retrieving user by his ID.
	 * 
	 * @param userId - id of user in DB.
	 * @return - data transfer object containing data of found user.
	 */
	UserDTO findUserById(String userId);

	/**
	 * Method used for retrieving paginated user account data.
	 * 
	 * @param searchString - value by which users will be searched.
	 * @param searchBy     - field name by which users will be searched.
	 * @param pageable     - instance of page request.
	 * @return - paginated user data.
	 */
	Page<UserDTO> getUsers(String searchString, String searchBy, Pageable pageable);

	/**
	 * Method used for deleting user from DB by his ID.
	 * 
	 * @param userId - ID of user whos account will be removed.
	 */
	void deleteUser(String userId);

	/**
	 * Method used for changing user password by admin.
	 * 
	 * @param model  - new password object.
	 * @param userId - ID of user whos password will be changed.
	 * @return data transfer object of user whos password was changed.
	 */
	UserDTO updateUserPassword(PasswordRequestModel model, String userId);

	/**
	 * Method used for access and refresh token revocation. Also all user approvals will be removed.
	 * @param user - user instance who's going to be signed out from page.
	 */
	void signOutUser(AppUser user);

	/**
	 * Method used to remove access and refresh tokens sent in http headers.
	 * @param authorization - http servlet instance object with http headers containing access token.
	 * @return - oauth access token which should be revoked.
	 */
	OAuth2AccessToken removeAccessTokens(String authorization);

	/**
	 * Method used for requesting new access token.
	 * @param request - http servlet request containing headers with access token.
	 * @param signedIn - instance of user who's access token will be renewed.
	 * @param accessToken - old access token instance.
	 * @return - instance of new access token.
	 */
	OAuth2AccessToken requestNewAccessToken(HttpServletRequest request, AppUser signedIn,
			OAuth2AccessToken accessToken);

	Optional<AppUser> findById(String userId);
}
