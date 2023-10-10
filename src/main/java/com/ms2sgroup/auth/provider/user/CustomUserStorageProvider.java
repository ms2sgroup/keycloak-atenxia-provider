package com.ms2sgroup.auth.provider.user;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.text.DateFormat;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
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

public class CustomUserStorageProvider implements UserStorageProvider, 
  UserLookupProvider, 
  CredentialInputValidator,
  UserQueryProvider {
    
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
            PreparedStatement st = c.prepareStatement("select username, '','', email from atenxia_user where is_active=true and username = ?");
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
            PreparedStatement st = c.prepareStatement("select username, '','', email from atenxia_user where is_active=true and email = ?");
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
            PreparedStatement st = c.prepareStatement("select password from users where username = ?");
            st.setString(1, username);
            st.execute();
            ResultSet rs = st.getResultSet();
            if ( rs.next()) {
                String pwd = rs.getString(1);
                return pwd.equals(credentialInput.getChallengeResponse());
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
        
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement("select username, '','', email from atenxia_user where is_active=true and username like ? order by username limit ? offset ?");
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
            PreparedStatement st = c.prepareStatement("select username, '','', email from atenxia_user where is_active=true and username like ? order by username limit ? offset ?");
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
        return getGroupMembersStream(realm, null, firstResult, maxResults);
    }

    @Override
    public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
        return Stream.empty();
    }
    
    //------------------- Implementation 
    private UserModel mapUser(RealmModel realm, ResultSet rs) throws SQLException {
        
        DateFormat fmt = new SimpleDateFormat("yyyy-MM-dd");
        CustomUser user = new CustomUser.Builder(ksession, realm, model, rs.getString("username"))
          .email(rs.getString("email"))
          .firstName(rs.getString("first_name"))
          .lastName(rs.getString("last_name"))
          .build();
        
        ResultSet roles = null;
        try ( Connection c = DbUtil.getConnection(this.model)) {
            PreparedStatement st = c.prepareStatement("select is_center_admin, is_parent, is_professional, is_teacher, is_staff from atenxia_user where is_active = true and username=?");
            st.setString(1, rs.getString("username"));
            st.execute();
            roles = st.getResultSet();
        } catch (SQLException ex) {
            throw new RuntimeException("Database error:" + ex.getMessage(), ex);
        }
        
       
        if(roles!=null)
        {
            boolean center_admin = (roles.getBoolean("is_center_admin")) ? true:false;
            boolean parent = (roles.getBoolean("is_parent")) ? true:false;
            boolean professional = (roles.getBoolean("is_professional")) ? true:false;
            boolean teacher = (roles.getBoolean("is_teacher")) ? true:false;
            boolean admin = (roles.getBoolean("is_staff")) ? true:false;
            
            log.info("lookup user by username roles " + center_admin +"," +parent+"," +professional+"," +teacher+"," +admin);
            
            user.deleteRoleMapping(getRoleFromString(realm, this.client, this.role_teacher));
            user.deleteRoleMapping(getRoleFromString(realm, this.client, this.role_parent));
            user.deleteRoleMapping(getRoleFromString(realm, this.client, this.role_professional));
            user.deleteRoleMapping(getRoleFromString(realm, this.client, this.role_center_admin));
            user.deleteRoleMapping(getRoleFromString(realm, this.client, this.role_admin));
            
            if (teacher)
            	user.grantRole(getRoleFromString(realm, this.client, this.role_teacher));
            if (parent)
            	user.grantRole(getRoleFromString(realm, this.client, this.role_parent));
            if (professional)
            	user.grantRole(getRoleFromString(realm, this.client, this.role_professional));
            if (center_admin)
            	user.grantRole(getRoleFromString(realm, this.client, this.role_center_admin));
            if (admin)
            	user.grantRole(getRoleFromString(realm, this.client, this.role_admin));
        }
      
        return user;
    }
    
    
    private RoleModel getRoleFromString(RealmModel realm, String clientId, String roleName) {
   	log.info("getRoleFromString " + roleName);
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
