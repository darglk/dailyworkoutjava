package com.darglk.dailyworkoutjava.domain.user.repository;

import com.darglk.dailyworkoutjava.domain.user.entity.AccountActivationToken;
import com.darglk.dailyworkoutjava.domain.user.entity.AppUser;
import org.springframework.data.repository.CrudRepository;

/**
 * Repository for AccountActivationToken class.
 * @author Dariusz Kulig
 *
 */
public interface AccountActivationTokenRepository extends CrudRepository<AccountActivationToken, String> {
	/**
	 * Method used for finding activation token instance by token string value.
	 * @param token - string value used to be found in db.
	 * @return - found account activation token instance.
	 */
	AccountActivationToken findByToken(String token);

	/**
	 * Method used for finding activation token instance by given user id.
	 * @param user - user instance with id used to be found in db.
	 * @return - found account activation token instance.
	 */
	AccountActivationToken findByUser(AppUser user);
}