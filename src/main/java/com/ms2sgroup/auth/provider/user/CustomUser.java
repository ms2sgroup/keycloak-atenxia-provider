package com.ms2sgroup.auth.provider.user;

import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
public class CustomUser {

	private String username;
	private String email;
	private String firstName;
	private String lastName;
	private boolean centerAdmin;
	private boolean parent;
	private boolean professional;
	private boolean teacher;
	private boolean admin;
	private Long created;

	public CustomUser(String username, String email, String firstName, String lastName, boolean centerAdmin, boolean parent, boolean professional, boolean teacher, boolean admin) {

		this.username = username;
		this.email = email;
		this.firstName = firstName;
		this.lastName = lastName;
		this.centerAdmin = centerAdmin;
		this.parent = parent;
		this.professional = professional;
		this.teacher = teacher;
		this.admin = admin;
		this.created = System.currentTimeMillis();
	}
}