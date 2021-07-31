package com.darglk.dailyworkoutjava.domain.user.entity;

import com.fasterxml.jackson.annotation.JsonIgnore;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;

import javax.persistence.*;
import javax.validation.constraints.NotNull;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * Role entity used by AppUser.
 * 
 * @author darglk
 *
 */
@Entity
@Table(name = "roles")
@Data
@NoArgsConstructor
public class Role implements GrantedAuthority {

	/**
	 * 
	 */
	private static final long serialVersionUID = 8654143176391259743L;

	/**
	 * id - role ID in DB.
	 */
	@Id
	@Column(name = "role_id")
	private String id = UUID.randomUUID().toString();

	/**
	 * name - name of role. Search RoleName enum for role names defined for this
	 * application.
	 */
	@Column(name = "role_name", length = 30, unique = true, nullable = false)
	@NotNull
	@Enumerated(EnumType.STRING)
	private RoleName name;

	/**
	 * users - list of users associated with role instance.
	 */
	@ManyToMany(mappedBy = "roles", fetch = FetchType.LAZY, cascade = CascadeType.ALL)
	@JsonIgnore
	private Set<AppUser> users = new HashSet<>();

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + ((id == null) ? 0 : id.hashCode());
		return result;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj)
			return true;
		if (obj == null)
			return false;
		if (getClass() != obj.getClass())
			return false;
		Role other = (Role) obj;
		if (id == null) {
			if (other.id != null)
				return false;
		} else if (!id.equals(other.id))
			return false;
		return true;
	}

	@Override
	public String getAuthority() {
		return getName().name();
	}
}
