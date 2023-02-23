/*
 * Copyright 2016 Red Hat, Inc. and/or its affiliates
 * and other contributors as indicated by the @author tags.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package user_storage_keycloak_mysql;

import org.jboss.logging.Logger;
import org.keycloak.component.ComponentModel;
import org.keycloak.connections.jpa.JpaConnectionProvider;
import org.keycloak.credential.CredentialInput;
import org.keycloak.credential.CredentialInputUpdater;
import org.keycloak.credential.CredentialInputValidator;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.GroupModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserCredentialModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.cache.CachedUserModel;
import org.keycloak.models.cache.OnUserCache;
import org.keycloak.models.credential.PasswordCredentialModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.UserStorageProvider;
import org.keycloak.storage.user.UserLookupProvider;
import org.keycloak.storage.user.UserQueryProvider;
import org.keycloak.storage.user.UserRegistrationProvider;

import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;

public class MyUserStorageProvider implements UserStorageProvider,
        UserLookupProvider,
        UserRegistrationProvider,
        UserQueryProvider,
        CredentialInputUpdater,
        CredentialInputValidator,
        OnUserCache
{
    private static final Logger logger = Logger.getLogger(MyUserStorageProvider.class);
    public static final String PASSWORD_CACHE_KEY = UserAdapter.class.getName() + ".password";

    protected EntityManager em;

    protected ComponentModel model;
    protected KeycloakSession session;
    
    //
    protected Map<String, UserModel> loadedUsers = new HashMap<>();

    MyUserStorageProvider(KeycloakSession session, ComponentModel model) {
        this.session = session;
        this.model = model;
        em = session.getProvider(JpaConnectionProvider.class, "app").getEntityManager();
    }

    @Override
    public void preRemove(RealmModel realm) {

    }

    @Override
    public void preRemove(RealmModel realm, GroupModel group) {

    }

    @Override
    public void preRemove(RealmModel realm, RoleModel role) {

    }

    @Override
    public void close() {
    }

    @Override
    public UserModel getUserById(RealmModel realm,String id) {
        logger.info("getUserById: " + id);
        String persistenceId = StorageId.externalId(id);
        User entity = em.find(User.class, persistenceId);
        if (entity == null) {
            logger.info("could not find user by id: " + id);
            return null;
        }
        return new UserAdapter(session, realm, model, entity);
    }
    @Override
    public UserModel getUserByUsername(RealmModel realm,String username) {
        logger.info("getUserByUsername: " + username);
        TypedQuery<User> query = em.createNamedQuery("getUserByUsername", User.class);
        query.setParameter("username", username);
//        realm.getAttribute(name, defaultValue)
        List<User> result = query.getResultList();
        if (result.isEmpty()) {
            logger.info("could not find username: " + username);
            return null;
        }

        return new UserAdapter(session, realm, model, result.get(0));
    }

    @Override
    public UserModel getUserByEmail(RealmModel realm,String email) {
        TypedQuery<User> query = em.createNamedQuery("getUserByEmail", User.class);
        query.setParameter("email", email);
        List<User> result = query.getResultList();
        if (result.isEmpty()) return null;
        return new UserAdapter(session, realm, model, result.get(0));
    }

    @Override
    public UserModel addUser(RealmModel realm, String username) {
        User entity = new User();
     //comment the row down
        entity.setId(UUID.randomUUID().toString());
        entity.setUsername(username);
        em.persist(entity);
        logger.info("added user: " + username);
        logger.info(entity.getPassword());
        logger.info(entity.getUsername());
        return new UserAdapter(session, realm, model, entity);
    }

    @Override
    public boolean removeUser(RealmModel realm, UserModel user) {
        String persistenceId = StorageId.externalId(user.getId());
        User entity = em.find(User.class, persistenceId);
        if (entity == null) return false;
        em.remove(entity);
        return true;
    }

    @Override
    public void onCache(RealmModel realm, CachedUserModel user, UserModel delegate) {
        String password = ((UserAdapter)delegate).getPassword();
        if (password != null) {
            user.getCachedWith().put(PASSWORD_CACHE_KEY, password);
        }
    }

    @Override
    public boolean supportsCredentialType(String credentialType) {
    	return PasswordCredentialModel.TYPE.equals(credentialType);
//        return CredentialModel.PASSWORD.equals(credentialType);
    }

    @Override
    public boolean updateCredential(RealmModel realm, UserModel user, CredentialInput input) {
        if (!supportsCredentialType(input.getType()) || !(input instanceof UserCredentialModel)) return false;
        UserCredentialModel cred = (UserCredentialModel)input;
        UserAdapter adapter = getUserAdapter(user);
        adapter.setPassword(cred.getValue());

        return true;
    }

    public UserAdapter getUserAdapter(UserModel user) {
        UserAdapter adapter = null;
        if (user instanceof CachedUserModel) {
            adapter = (UserAdapter)((CachedUserModel)user).getDelegateForUpdate();
        } else {
            adapter = (UserAdapter)user;
        }
        return adapter;
    }

    @Override
    public void disableCredentialType(RealmModel realm, UserModel user, String credentialType) {
        if (!supportsCredentialType(credentialType)) return;

        getUserAdapter(user).setPassword(null);

    }

    @Override
	public Stream<String> getDisableableCredentialTypesStream(RealmModel realm,UserModel user){
    	return getDisableableCredentialTypes(realm, user).stream();
    }

    public Set<String> getDisableableCredentialTypes(RealmModel realm, UserModel user) {
        if (getUserAdapter(user).getPassword() != null) {
            Set<String> set = new HashSet<>();
            set.add(PasswordCredentialModel.TYPE);
            return set;
        } else {
            return Collections.emptySet();
        }
    }

    @Override
    public boolean isConfiguredFor(RealmModel realm, UserModel user, String credentialType) {
        return supportsCredentialType(credentialType) && getPassword(user) != null;
    }

    @Override
    public boolean isValid(RealmModel realm, UserModel user, CredentialInput input) {
        if (!supportsCredentialType(input.getType()) || !(input instanceof UserCredentialModel)) return false;
        UserCredentialModel cred = (UserCredentialModel)input;
        String password = getPassword(user);
        return password != null && password.equals(cred.getValue());
    }

    public String getPassword(UserModel user) {
        String password = null;
        if (user instanceof CachedUserModel) {
            password = (String)((CachedUserModel)user).getCachedWith().get(PASSWORD_CACHE_KEY);
        } else if (user instanceof UserAdapter) {
            password = ((UserAdapter)user).getPassword();
        }
        return password;
    }

    @Override
    public int getUsersCount(RealmModel realm) {
        Object count = em.createNamedQuery("getUserCount")
                .getSingleResult();
        return ((Number)count).intValue();
    }
    //here problem
    @Override
    public Stream<UserModel> getUsersStream(RealmModel realm) {
        return getUsersStream(realm, -1, -1);
    }

   //here problem
    @Override
    public Stream<UserModel> getUsersStream(RealmModel realm, Integer firstResult, Integer maxResults) {

        TypedQuery<User> query = em.createNamedQuery("getAllUsers", User.class);
        if (firstResult != -1) {
            query.setFirstResult(firstResult);
        }
        if (maxResults != -1) {
            query.setMaxResults(maxResults);
        }
        List<User> results = query.getResultList();
        List<UserModel> users = new LinkedList<>();
        for (User entity : results) users.add(new UserAdapter(session, realm, model, entity));
        return users.stream();
    }

    //here problem
    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm,String search) {
        return searchForUserStream(realm,search, -1, -1);
    }

    
	@Override
	public Stream<UserModel> searchForUserStream(RealmModel realm, String search, Integer firstResult,Integer maxResults) {
		//my code
		 TypedQuery<User> query = em.createNamedQuery("getAllUsers", User.class);
		 Stream<UserModel> results;
	        if (firstResult != -1) {
	            query.setFirstResult(firstResult);
	        }
	        if (maxResults != -1) {
	            query.setMaxResults(maxResults);
	        }
	        if(search.equals("*")){
	            results = query.getResultList().stream().map(user -> new UserAdapter(session, realm, model, user));
	        }else {
	        	results = query.getResultList().stream().filter(user->user.getUsername().contains(search)).map(user -> new UserAdapter(session, realm, model, user));
	        }
	   
	        
	        return results;
	      
	}

    @Override
    public Stream<UserModel> searchForUserStream(RealmModel realm,Map<String, String> params) {
        return Collections.EMPTY_LIST.stream();
    }

    //problem
    @Override
   	public Stream<UserModel> searchForUserStream(RealmModel realm, Map<String, String> params, Integer firstResult,Integer maxResults) {
    	 return Collections.EMPTY_LIST.stream();
   	}
  

    @Override
    public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group) {
        return Collections.EMPTY_LIST.stream();
    }
    
    @Override
	public Stream<UserModel> searchForUserByUserAttributeStream(RealmModel realm, String attrName, String attrValue) {
		return Collections.EMPTY_LIST.stream();
	}


	@Override
	public Stream<UserModel> getGroupMembersStream(RealmModel realm, GroupModel group, Integer firstResult,
			Integer maxResults) {
		// TODO Auto-generated method stub
		return null;
	}


}
