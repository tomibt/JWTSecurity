package com.example.jwtSecurity.entity;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.fasterxml.jackson.annotation.JsonIgnore;

import lombok.Data;

@Data
public class UserPrincipal implements UserDetails {

	private Long id;
	private String name;
	private String username;
	@JsonIgnore
	private String email;
	private String role;

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {

		return Collections.singletonList(new SimpleGrantedAuthority(this.role));
	}

	public UserPrincipal(Long id, String name, String username, String email, String role) {
		this.id = id;
		this.name = name;
		this.username = username;
		this.email = email;
		this.role = role;
	}

	public static UserPrincipal create(User user) {

		List<GrantedAuthority> authorities = user.getRoles().stream()
				.map(role -> new SimpleGrantedAuthority(role.getRole().name())).collect(Collectors.toList());

//		user_roles- table
//		1    1
//		1	 2

//		Dimitar - roles: user, admin

		return new UserPrincipal(user.getId(), user.getName(), user.getUsername(), user.getEmail(),
				authorities.toString());

	}

	// TODO To be implemented

	@Override
	public boolean isAccountNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isAccountNonLocked() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isCredentialsNonExpired() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public boolean isEnabled() {
		// TODO Auto-generated method stub
		return true;
	}

	@Override
	public String getPassword() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getUsername() {
		// TODO Auto-generated method stub
		return null;
	}

}
