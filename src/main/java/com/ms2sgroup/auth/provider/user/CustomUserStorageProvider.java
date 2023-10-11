package com.ms2sgroup.auth.provider.user;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import org.keycloak.component.ComponentModel;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.models.ClientModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ms2sgroup.auth.provider.user.util.PBKDF2SHA256HashingUtil;

public class CustomUserStorageProvider implements UserStorageProvider, 
  UserLookupProvider, 
  CredentialInputValidator,
  UserQueryProvider  {
    
    private static final Logger log = LoggerFactory.getLogger(CustomUserStorageProvider.class);
    private KeycloakSession ksession;
    private ComponentModel model;
    
    private final String role_teacher = "TEACHER";
    private final String role_professional = "PROFESSIONAL";
    private final String role_admin = "ADMIN";
    private final String role_parent="PARENT";
    private final String role_center_admin="CENTER_ADMIN";
    
    private final String client = "client-atenxia";

    public CustomUserStorageProvider(KeycloakSession ksession, ComponentModel model) {
        this.ksession = ksession;
        this.model = model;
    }

    @Override
    public void close() {
        log.info("[I30] close()");
    }

    @Override
    public UserModel getUserById(RealmModel realm, String id) {
        log.info("[I35] getUserById({})",id);
        StorageId sid = new StorageId(id);
        return getUserByUsername(realm, sid.getExternalId());
    }

    @Override
    public UserModel getUserByUsername(RealmModel realm, String username) {
        log.info("[I41] getUserByUsername({})",username);
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement("select username, '','', email, is_center_admin, is_parent, is_professional, is_teacher, is_staff  from atenxia_user where is_active=true and username = ?");
            st.setString(1, username);
            st.execute();
            ResultSet rs = st.getResultSet();
            if ( rs.next()) {
                return mapUser(realm,rs);
            }
            else {
                return null;
            }
        }
        catch(SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
        }
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm, String email) {
        log.info("[I48] getUserByEmail({})",email);
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement("select username, '','', email, is_center_admin, is_parent, is_professional, is_teacher, is_staff from atenxia_user where is_active=true and email = ?");
            st.setString(1, email);
            st.execute();
            ResultSet rs = st.getResultSet();
            if ( rs.next()) {
                return mapUser(realm,rs);
            }
            else {
                return null;
            }
        }
        catch(SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
        }
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
        log.info("[I57] supportsCredentialType({})",credentialType);
        return PasswordCredentialModel.TYPE.endsWith(credentialType);
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        log.info("[I57] isConfiguredFor(realm={},user={},credentialType={})",realm.getName(), user.getUsername(), credentialType);
        // In our case, password is the only type of credential, so we allways return 'true' if
        // this is the credentialType
        return supportsCredentialType(credentialType);
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput credentialInput) {
        log.info("[I57] isValid(realm={},user={},credentialInput.type={})",realm.getName(), user.getUsername(), credentialInput.getType());
        if( !this.supportsCredentialType(credentialInput.getType())) {
            return false;
        }
        StorageId sid = new StorageId(user.getId());
        String username = sid.getExternalId();
        
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement("select password from atenxia_user where is_active=true and username = ?");
            st.setString(1, username);
            st.execute();
            ResultSet rs = st.getResultSet();
            if ( rs.next()) {
                String pwd = rs.getString(1);
                String hash = Optional.ofNullable(pwd).orElse("");
                String[] components = hash.split("\\$");
                return new PBKDF2SHA256HashingUtil(credentialInput.getChallengeResponse(), components[2], Integer.valueOf(components[1])).validatePassword(components[3]);
                
                //return pwd.equals(credentialInput.getChallengeResponse());
            }
            else {
                return false;
            }
        }
        catch(SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
        }
    }

    // UserQueryProvider implementation
    
    @Override
    public int getUsersCount(RealmModel realm) {
        log.info("[I93] getUsersCount: realm={}", realm.getName() );
        try ( Connection c = DbUtil.getConnection(this.model)) {
            Statement st = c.createStatement();
            st.execute("select count(*) from atenxia_user where is_active=true");
            ResultSet rs = st.getResultSet();
            rs.next();
            return rs.getInt(1);
        }
        catch(SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
        }
    }

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult, Integer maxResults) {
        log.info("[I113] getUsers: realm={}", realm.getName());
        
        if (maxResults == null)
            maxResults = 10;
        
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement("select username, '','', email, is_center_admin, is_parent, is_professional, is_teacher, is_staff from atenxia_user where is_active=true order by username limit ? offset ?");
            st.setInt(1, maxResults);
            st.setInt(2, firstResult);
            st.execute();
            ResultSet rs = st.getResultSet();
            List<UserModel> users = new ArrayList<>();
            while(rs.next()) {
                users.add(mapUser(realm,rs));
            }
            return users.stream();
        }
        catch(SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(),ex);
        }
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, String search, Integer firstResult, Integer maxResults) {
        log.info("[I139] searchForUser: realm={}", realm.getName());

        try (Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement("select username, '','', email, is_center_admin, is_parent, is_professional, is_teacher, is_staff from atenxia_user where is_active=true and username like ? order by username limit ? offset ?");
            st.setString(1, search);
            st.setInt(2, maxResults);
            st.setInt(3, firstResult);
            st.execute();
            ResultSet rs = st.getResultSet();
            List<UserModel> users = new ArrayList<>();
            while (rs.next()) {
                users.add(mapUser(realm, rs));
            }
            return users.stream();
        } catch (SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(), ex);
        }
    }

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params, Integer firstResult, Integer maxResults) {
	if (params.containsKey(UserModel.USERNAME)) {
	    return searchForUserStream(realm, params.get(UserModel.USERNAME), firstResult, maxResults);
	} 
	else 
	{
	    return getGroupMembersStream(realm, null, firstResult, maxResults);
	}
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
        return Stream.empty();
    }
    
    //------------------- Implementation 
    private UserModel mapUser(RealmModel realm, ResultSet rs) throws SQLException {
        
	
	String username= rs.getString("username");
	String email = rs.getString("email");
	boolean centerAdmin = rs.getBoolean("is_center_admin");
        boolean parent = rs.getBoolean("is_parent");
        boolean professional = rs.getBoolean("is_professional");
        boolean teacher = rs.getBoolean("is_teacher");
        boolean admin = rs.getBoolean("is_staff");
        
	CustomUser userAux = new CustomUser(username, email,"","", centerAdmin, parent, professional, teacher, admin);
        CustomUserAdapter user = new CustomUserAdapter(ksession, realm, model, userAux);
                
        /*ResultSet roles = null;
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement("select is_center_admin, is_parent, is_professional, is_teacher, is_staff from atenxia_user where is_active = true and username=?");
            st.setString(1, username);
            st.execute();
            roles = st.getResultSet();
        } catch (SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(), ex);
        }*/
        
        RoleModel roleTeacher = getRoleFromString(realm, this.client, this.role_teacher);
        RoleModel roleParent = getRoleFromString(realm, this.client, this.role_parent);
        RoleModel roleProfessional = getRoleFromString(realm, this.client, this.role_professional);
        RoleModel roleCenterAdmin = getRoleFromString(realm, this.client, this.role_center_admin);
        RoleModel roleAdmin = getRoleFromString(realm, this.client, this.role_admin);
          
        try
        {
            user.deleteRoleMapping(roleTeacher);
            user.deleteRoleMapping(roleParent);
            user.deleteRoleMapping(roleProfessional);
            user.deleteRoleMapping(roleCenterAdmin);
            user.deleteRoleMapping(roleAdmin);
        }    
        catch(Exception e)
        {
        }
            
        if (teacher)
            user.grantRole(roleTeacher);
        if (parent)
            user.grantRole(roleParent);
        if (professional)
            user.grantRole(roleProfessional);
        if (centerAdmin)
            user.grantRole(roleCenterAdmin);
        if (admin)
            user.grantRole(roleAdmin);
        
        return user;
    }
    
    
    private RoleModel getRoleFromString(RealmModel realm, String clientId, String roleName) {
   	RoleModel role = null;
           ClientModel client = realm.getClientByClientId(clientId);
           if (client != null) {
           	try
                   {
           	    role = client.getRole(roleName);
                   }
                   catch(Exception e)
                   {
                   }
           }
           
           return role;
       }
    
    

}
