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
import org.keycloak.common.util.MultivaluedHashMap;
import org.keycloak.component.ComponentModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.storage.StorageId;
import org.keycloak.storage.adapter.AbstractUserAdapterFederatedStorage;

import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

public class UserAdapter extends AbstractUserAdapterFederatedStorage {
    private static final Logger logger = Logger.getLogger(UserAdapter.class);
    protected User entity;
    protected String keycloakId;

    public UserAdapter(KeycloakSession session, RealmModel realm, ComponentModel model, User entity) {
        super(session, realm, model);
        this.entity = entity;
        keycloakId = StorageId.keycloakId(model, String.valueOf(entity.getId()));
    }
    
    public String getPassword() {
        return entity.getPassword();
    }

    public void setPassword(String password) {
        entity.setPassword(password);
    }

    @Override
    public String getUsername() {
        return entity.getUsername();
    }

    @Override
    public void setUsername(String username) {
        entity.setUsername(username);

    }

    @Override
    public void setEmail(String email) {
        entity.setEmail(email);
    }

    @Override
    public String getEmail() {
        return entity.getEmail();
    }

    @Override
    public String getId() {
        return keycloakId;
    }

    @Override
    public void setSingleAttribute(String name, String value) {
        if (name.equals("phone")) {
            entity.setPhone(value);
        }if(name.equals("email")) {
        	entity.setEmail(value);
        } else {
            super.setSingleAttribute(name, value);
        }
    }

    @Override
    public void removeAttribute(String name) {
        if (name.equals("phone")) {
            entity.setPhone(null);
        }if(name.equals("email")) {
        	entity.setEmail(null);
        } else {
            super.removeAttribute(name);
        }
    }

    @Override
    public void setAttribute(String name, List<String> values) {
        if (name.equals("phone")) {
            entity.setPhone(values.get(0));
        } if(name.equals("email")) {
        	entity.setEmail(values.get(0));
        }else {
            super.setAttribute(name, values);
        }
    }

    @Override
    public String getFirstAttribute(String name) {
        if (name.equals("phone")) {
            return entity.getPhone();
        }if(name.equals("email")) {
        	return entity.getEmail();
        } else {
            return super.getFirstAttribute(name);
        }
    }
    
   

    @Override
    public Map<String, List<String>> getAttributes() {
    	MultivaluedHashMap<String, String> attributes = new MultivaluedHashMap<>();
    	attributes.add(UserModel.USERNAME, getUsername());
		attributes.add(UserModel.EMAIL, getEmail());
        attributes.add("phone", entity.getPhone());
        return attributes;
      
    }
    

    
    @Override
	public Stream<String> getAttributeStream(String name) {
		Map<String, List<String>> attributes = getAttributes();
		return (attributes.containsKey(name)) ? attributes.get(name).stream() : Stream.empty();
	}

    @Override
    public List<String> getAttribute(String name) {
        if (name.equals("phone")) {
            List<String> phone = new LinkedList<>();
            phone.add(entity.getPhone());
            return phone;
        } else {
            return super.getAttribute(name);
        }
    }
}
