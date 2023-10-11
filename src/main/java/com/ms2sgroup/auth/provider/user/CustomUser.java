package com.ms2sgroup.auth.provider.user;

import java.util.List;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class CustomUser {

	private String username;
	private String email;
	private String firstName;
	private String lastName;
	private List<String> roles;

	public CustomUser(String username, String email, String firstName, String lastName, List<String> roles) {

		this.username = username;
		this.email = email;
		this.firstName = firstName;
		this.lastName = lastName;
		this.roles = roles;
	}
}