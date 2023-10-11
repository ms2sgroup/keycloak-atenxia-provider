package com.ms2sgroup.auth.provider.user;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;

class CustomUserAdapter extends AbstractUserAdapterFederatedStorage  {
    
    private final CustomUser user;


    public CustomUserAdapter(KeycloakSession session, RealmModel realm, ComponentModel model, CustomUser user) {
	super(session, realm, model);
	this.user = user;
    }

    @Override
    public String getUsername() {
	return user.getUsername();
    }

    @Override
    public void setUsername(String username) {
	user.setUsername(username);
    }

    @Override
    public String getFirstName() {
	return user.getFirstName();
    }

    @Override
    public void setFirstName(String firstName) {
	user.setFirstName(firstName);
    }

    @Override
    public String getLastName() {
	return user.getLastName();
    }

    @Override
    public void setLastName(String lastName) {
	user.setLastName(lastName);
    }

    @Override
    public String getEmail() {
	return user.getEmail();
    }

    @Override
    public void setEmail(String email) {
	user.setEmail(email);
    }

    @Override
    public boolean isEmailVerified() {
	return true;
    }

    @Override
    public void setEmailVerified(boolean verified) {
    }

    
    @Override
    public void setAttribute(String name, List<String> values) {
	String value = values != null && !values.isEmpty() ? values.get(0) : null;
	switch (name) {
		case UserModel.USERNAME -> setUsername(value);
		case UserModel.LAST_NAME -> setLastName(value);
		case UserModel.FIRST_NAME -> setFirstName(value);
		case UserModel.EMAIL -> setEmail(value);
		default -> super.setAttribute(name, values);
	}
    }

    @Override
    public String getFirstAttribute(String name) {
	return switch (name) {
		case UserModel.USERNAME -> getUsername();
		case UserModel.LAST_NAME -> getLastName();
		case UserModel.FIRST_NAME -> getFirstName();
		case UserModel.EMAIL -> getEmail();
		default -> super.getFirstAttribute(name);
	};
    }

    @Override
    public Stream<String> getAttributeStream(String name) {
	return switch (name) {
		case UserModel.USERNAME -> Stream.of(getUsername());
		case UserModel.LAST_NAME -> Stream.of(getLastName());
		case UserModel.FIRST_NAME -> Stream.of(getFirstName());
		case UserModel.EMAIL -> Stream.of(getEmail());
		default -> super.getAttributeStream(name);
	};
    }

    @Override
    public Map<String, List<String>> getAttributes() {
	MultivaluedHashMap<String, String> attributes = getFederatedStorage().getAttributes(realm, this.getId());
	if (attributes == null) {
		attributes = new MultivaluedHashMap<>();
	}
	attributes.add(UserModel.USERNAME, getUsername());
	attributes.add(UserModel.EMAIL, getEmail());
	attributes.add(UserModel.FIRST_NAME, getFirstName());
	attributes.add(UserModel.LAST_NAME, getLastName());
	return attributes;
    }


    @Override
    public void setSingleAttribute(String name, String value) {
	switch (name) {
		case UserModel.USERNAME -> setUsername(value);
		case UserModel.LAST_NAME -> setLastName(value);
		case UserModel.FIRST_NAME -> setFirstName(value);
		case UserModel.EMAIL -> setEmail(value);
		default -> super.setSingleAttribute(name, value);
	}
    }
    
}
