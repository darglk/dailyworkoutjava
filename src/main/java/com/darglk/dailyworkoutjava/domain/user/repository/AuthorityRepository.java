package com.darglk.dailyworkoutjava.domain.user.repository;


import com.darglk.dailyworkoutjava.domain.user.entity.Authority;
import com.darglk.dailyworkoutjava.domain.user.entity.AuthorityName;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface AuthorityRepository extends JpaRepository<Authority, String> {
	Authority findByName(AuthorityName authorityName);
}
