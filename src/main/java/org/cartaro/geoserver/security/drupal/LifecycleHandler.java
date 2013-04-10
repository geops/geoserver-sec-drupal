package org.cartaro.geoserver.security.drupal;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Arrays;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.SortedSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.geoserver.config.impl.GeoServerLifecycleHandler;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.GeoServerAuthenticationProvider;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.auth.GeoServerRootAuthenticationProvider;
import org.geoserver.security.config.SecurityAuthProviderConfig;
import org.geoserver.security.config.SecurityUserGroupServiceConfig;
import org.geotools.util.logging.Logging;

public class LifecycleHandler implements GeoServerLifecycleHandler {
	protected static Logger LOGGER = Logging.getLogger("org.geoserver.security");

	public void onReset() {
		// TODO Auto-generated method stub
		
	}

	public void onDispose() {
		// TODO Auto-generated method stub
		
	}

	public void onReload() {
		reloadAuthenticationProviders();
		reloadUserGroupServices();
	}
	
	private void reloadUserGroupServices() {
		LOGGER.info("Reloading user group services");
		
		GeoServerSecurityManager securityManager = GeoServerExtensions.bean(GeoServerSecurityManager.class);
		LOGGER.info("GeoServerSecurityManager: "+System.identityHashCode(securityManager));
		
		SortedSet<String> userGroupServicesNames;
		try {
			userGroupServicesNames = securityManager.listUserGroupServices();
		} catch (IOException e) {
			LOGGER.log(Level.SEVERE, "It was impossible to get names of user group services, aborting user group service reload. Verfiy access permissions on data/usergroup/.", e);
			return;
		}
		Set<String> loadedUserGroupServicesNames = new HashSet<String>();
		Field userGroupServicesField;
		try {
			userGroupServicesField = securityManager.getClass().getDeclaredField("userGroupServices");
		} catch (SecurityException e) {
			LOGGER.log(Level.SEVERE, "Cannot modify user group services due to missing permissions.", e);
			return;
		} catch (NoSuchFieldException e) {
			LOGGER.log(Level.SEVERE, "Implementation regarding user group services changed. Drupal lib needs updating.", e);
			return;
		}
		userGroupServicesField.setAccessible(true);
		ConcurrentHashMap<String, GeoServerUserGroupService> loadedUserGroupServices;
		try {
			loadedUserGroupServices = (ConcurrentHashMap<String, GeoServerUserGroupService>) userGroupServicesField.get(securityManager);
			LOGGER.info("Present user group services: "+System.identityHashCode(loadedUserGroupServices));
			LOGGER.info("Present user group services: "+Arrays.toString(loadedUserGroupServices.keySet().toArray()));
		} catch (IllegalArgumentException e) {
			LOGGER.log(Level.SEVERE, "Object type messed up", e);
			return;
		} catch (IllegalAccessException e) {
			LOGGER.log(Level.SEVERE, "JVM bug: Access to field denied, despite marked as granted.", e);
			return;
		}
		LinkedList<String> toRemove = new LinkedList<String>();
		for(GeoServerUserGroupService ugs: loadedUserGroupServices.values()){
			LOGGER.info("Checking user group service for update/remove: "+ugs.getName());
			loadedUserGroupServicesNames.add(ugs.getName());
			if(userGroupServicesNames.contains(ugs.getName())){
				// Update
				LOGGER.info("Updating authentication provider "+ugs.getName());
				SecurityUserGroupServiceConfig config;
				try {
					config = securityManager.loadUserGroupServiceConfig(ugs.getName());
					ugs.initializeFromConfig(config);
				} catch (IOException e) {
					LOGGER.log(Level.WARNING, "Failed to update user group service "+ugs.getName(), e);
				}
			} else {
				// Remove as configuration got deleted
				LOGGER.info("Removing user group service "+ugs.getName());
				toRemove.add(ugs.getName());
			}
		}
		for(String name: toRemove){
			loadedUserGroupServices.remove(name);
		}
		
		// Add new configurations
		userGroupServicesNames.removeAll(loadedUserGroupServicesNames);
		for(String configName: userGroupServicesNames){
			GeoServerUserGroupService ugs;
			try {
				LOGGER.info("Adding user group service "+configName);
				ugs = securityManager.loadUserGroupService(configName);
				loadedUserGroupServices.put(configName, ugs);
				LOGGER.info("Present user group services (after put): "+System.identityHashCode(loadedUserGroupServices));
				LOGGER.info("Present user group services (after put): "+Arrays.toString(loadedUserGroupServices.keySet().toArray()));
				LOGGER.info("Added user group service "+ugs.getName());
			} catch (IOException e) {
				LOGGER.log(Level.WARNING, "Failed to load user group service for configuration "+configName, e);
			}
		}
	}

	private void reloadAuthenticationProviders(){
		LOGGER.info("Reloading authentication providers");
		
		GeoServerSecurityManager securityManager = GeoServerExtensions.bean(GeoServerSecurityManager.class);

		SortedSet<String> authenticationProviderNames;
		try {
			authenticationProviderNames = securityManager.listAuthenticationProviders();
		} catch (IOException e) {
			LOGGER.log(Level.SEVERE, "It was impossible to get names of authentication providers, aborting authentication provider reload. Verfiy access permissions on data/auth/.", e);
			return;
		}
		Set<String> loadedAuthenticationProviderNames = new HashSet<String>();
		List<GeoServerAuthenticationProvider> loadedAuthenticationProviders = securityManager.getAuthenticationProviders();
		LinkedList<GeoServerAuthenticationProvider> toRemove = new LinkedList<GeoServerAuthenticationProvider>();
		for(GeoServerAuthenticationProvider ap: loadedAuthenticationProviders){
			if(ap instanceof GeoServerRootAuthenticationProvider){
				// Skip of provider for root user that in special in that it does not have any configuration but is still present with an instance all the time
				continue;
			}
			loadedAuthenticationProviderNames.add(ap.getName());
			if(authenticationProviderNames.contains(ap.getName())){
				// Update
				LOGGER.info("Updating authentication provider "+ap.getName());
				SecurityAuthProviderConfig config;
				try {
					config = securityManager.loadAuthenticationProviderConfig(ap.getName());
					ap.initializeFromConfig(config);
				} catch (IOException e) {
					LOGGER.log(Level.WARNING, "Failed to update authentication provider "+ap.getName(), e);
				}
			} else {
				// Remove as configuration got deleted
				LOGGER.info("Removing authentication provider "+ap.getName());
				toRemove.add(ap);
			}
		}
		loadedAuthenticationProviders.removeAll(toRemove);
		
		// Add new configurations
		authenticationProviderNames.removeAll(loadedAuthenticationProviderNames);
		for(String configName: authenticationProviderNames){
			GeoServerAuthenticationProvider ap;
			try {
				LOGGER.info("Adding authentication provider "+configName);
				ap = securityManager.loadAuthenticationProvider(configName);
				loadedAuthenticationProviders.add(ap);
			} catch (IOException e) {
				LOGGER.log(Level.WARNING, "Failed to load authentication provider for configuration "+configName, e);
			}
		}
	}


}
