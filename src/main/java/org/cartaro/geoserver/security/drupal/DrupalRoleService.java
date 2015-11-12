package org.cartaro.geoserver.security.drupal;

import java.io.IOException;
import java.lang.reflect.Field;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Properties;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.ConcurrentModificationException;

import org.cartaro.geoserver.security.drupal.filter.DrupalRESTfulDefinitionSource;
import org.geoserver.catalog.Catalog;
import org.geoserver.catalog.impl.WorkspaceInfoImpl;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.AccessMode;
import org.geoserver.security.GeoServerRoleService;
import org.geoserver.security.GeoServerRoleStore;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.RESTfulDefinitionSource;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.config.SecurityRoleServiceConfig;
import org.geoserver.security.event.RoleLoadedEvent;
import org.geoserver.security.event.RoleLoadedListener;
import org.geoserver.security.file.FileWatcher;
import org.geoserver.security.impl.DataAccessRule;
import org.geoserver.security.impl.GeoServerRole;
import org.geotools.util.logging.Logging;
import org.springframework.util.StringUtils;

/**
 * Makes roles from Drupal instances available in GeoServer. This implementation
 * does aggregate roles from all Drupal instances.
 */
public class DrupalRoleService implements GeoServerRoleService {
	protected static Logger LOGGER = Logging
			.getLogger("org.geoserver.security");

	private String name;
	private GeoServerSecurityManager securityManager;
	private Set<RoleLoadedListener> listeners = Collections
			.synchronizedSet(new HashSet<RoleLoadedListener>());
	private String adminRole;
	private String groupAdminRole;

	public void initializeFromConfig(SecurityNamedServiceConfig config) {
		if (config instanceof SecurityRoleServiceConfig) {
			SecurityRoleServiceConfig c = (SecurityRoleServiceConfig) config;
			this.adminRole = c.getAdminRoleName();
			this.groupAdminRole = c.getGroupAdminRoleName();
		}
	}

	/**
	 * @return All user group services that bind to a Drupal instance.
	 */
	private List<DrupalUserGroupService> getDrupalUserGroupServices() {
		final List<DrupalUserGroupService> userGroupServices = new ArrayList<DrupalUserGroupService>();

		final GeoServerSecurityManager manager = GeoServerExtensions
				.bean(GeoServerSecurityManager.class);

		// terminate all running filewatchers in the securitymanager to avoid
		// accumulating threads watching users.xml
		// it would be far better to prevent new threads from being spawned on each reload,
		// but this is what we can do now.
		try {
			LOGGER.log(Level.FINEST, "Attempting to terminate existing filewatchers in userGroupServiceHelper");
			Field helperField = manager.getClass().getDeclaredField("userGroupServiceHelper");
			helperField.setAccessible(true);
			Object helper = helperField.get(manager);

			Field fileWatchersField = helper.getClass().getSuperclass().getDeclaredField("fileWatchers");
			fileWatchersField.setAccessible(true);
			@SuppressWarnings("unchecked")
			ArrayList<FileWatcher> fileWatchers = (ArrayList<FileWatcher>) fileWatchersField.get(helper);

			// terminate all threads
            for (FileWatcher fileWatcher : fileWatchers) {
                LOGGER.log(Level.FINE, "Terminating existing filewatcher on "+fileWatcher.getFileInfo());
                fileWatcher.setTerminate(true);
            }
			fileWatchers.clear();

		} catch (SecurityException e) {
			LOGGER.log(Level.WARNING, "Access to member forbidden. Could not stop filewatchers.", e);
		} catch (NoSuchFieldException e) {
			LOGGER.log(Level.WARNING, "Could not access member. Could not stop filewatchers.", e);
		}  catch (IllegalArgumentException e) {
			LOGGER.log(Level.WARNING, "invalid argument. Could not stop filewatchers.", e);
		} catch (IllegalAccessException e) {
			LOGGER.log(Level.WARNING, "attribute can not be accessed. Could not stop filewatchers.", e);
		} catch (ConcurrentModificationException e) {
            // two threads attempt to terminate the filewatchers concurrently.
            // this can be ignored as the otherthread will most certainly terminate the threads. Otherwise
            // they will be terminated during the next request [#3070068]
            LOGGER.log(Level.INFO, "Concurrent attempt to terminate filewatchers. Skipping termination.");
        }



		List<GeoServerUserGroupService> allUserGroupServices;
		try {
			// reload users and groups. this will spawn a new filewatcher on the users.xml file (geoserver 2.2)
			allUserGroupServices = manager
					.loadUserGroupServices();
		} catch (IOException e) {
			LOGGER.log(Level.INFO, "Could not read user group services. Drupal logins won't work.", e);
			return userGroupServices;
		}

		// Prevent GeoServer from caching the services' data because they change content without informing GeoServer.
		RESTfulDefinitionSource restPaths = GeoServerExtensions.bean(RESTfulDefinitionSource.class);
		if(restPaths instanceof DrupalRESTfulDefinitionSource){
			DrupalRESTfulDefinitionSource drupalRestPaths = (DrupalRESTfulDefinitionSource) restPaths;
			drupalRestPaths.invalidateRulesCache();
		} else {
			LOGGER.warning("Cannot update REST paths (access rules). Verify implementation of RESTfulDefinitionSource was overridden by applicationSecurityContextOverride.xml.");
		}

		for (final GeoServerUserGroupService userGroupService : allUserGroupServices) {
			if (userGroupService instanceof DrupalUserGroupService) {
				final DrupalUserGroupService drupalUserGroupService = (DrupalUserGroupService) userGroupService;
				userGroupServices.add(drupalUserGroupService);
			}
		}

		return userGroupServices;
	}

	public boolean canCreateStore() {
		// Signalizes that this is read only. Roles can be adjusted using Drupal
		// GUI.
		return false;
	}

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public void setSecurityManager(GeoServerSecurityManager securityManager) {
		this.securityManager = securityManager;
	}

	public GeoServerSecurityManager getSecurityManager() {
		return securityManager;
	}

	public GeoServerRoleStore createStore() throws IOException {
		return null;
	}

	public void registerRoleLoadedListener(RoleLoadedListener listener) {
		synchronized(listeners) {
			listeners.add(listener);
		}
	}

	public void unregisterRoleLoadedListener(RoleLoadedListener listener) {
		synchronized(listeners) {
			listeners.remove(listener);
		}
	}

	public SortedSet<String> getGroupNamesForRole(GeoServerRole role)
			throws IOException {
		// Drupal does not support groups so set is always empty
		return Collections.unmodifiableSortedSet(new TreeSet<String>());
	}

	public SortedSet<String> getUserNamesForRole(GeoServerRole role)
			throws IOException {
		TreeSet<String> userNames = new TreeSet<String>();
		for (DrupalUserGroupService service : getDrupalUserGroupServices()) {
			// Add all users of instance having the role
			SortedSet<String> serviceUserNames = service
					.getUserNamesForRole(role);
			userNames.addAll(serviceUserNames);
		}

		return Collections.unmodifiableSortedSet(userNames);
	}

	public SortedSet<GeoServerRole> getRolesForUser(String username)
			throws IOException {
		// Add role for instance user
		TreeSet<GeoServerRole> roles = new TreeSet<GeoServerRole>();
		for (DrupalUserGroupService service : getDrupalUserGroupServices()) {
			if (service.isResponsibleForUser(username)) {
				SortedSet<GeoServerRole> serviceUserNames = service
						.getRolesForUser(username);
				roles.addAll(serviceUserNames);
			}
		}
		return Collections.unmodifiableSortedSet(roles);
	}

	public SortedSet<GeoServerRole> getRolesForGroup(String groupname)
			throws IOException {
		// Drupal does not support groups so set is always empty
		return Collections.unmodifiableSortedSet(new TreeSet<GeoServerRole>());
	}

	public SortedSet<GeoServerRole> getRoles() throws IOException {
		TreeSet<GeoServerRole> foundRoles = new TreeSet<GeoServerRole>();
		for (DrupalUserGroupService service : getDrupalUserGroupServices()) {
			SortedSet<GeoServerRole> serviceUserNames = service.getRoles();
			foundRoles.addAll(serviceUserNames);
		}
		return Collections.unmodifiableSortedSet(foundRoles);
	}

	/**
	 * @return Mapping to nulls since Drupal does not support nested roles
	 */
	public Map<String, String> getParentMappings() throws IOException {
		HashMap<String, String> mapping = new HashMap<String, String>();
		for (GeoServerRole role : getRoles()) {
			mapping.put(role.getAuthority(), null);
		}
		return Collections.unmodifiableMap(mapping);
	}

	public GeoServerRole createRoleObject(String role) throws IOException {
		SortedSet<GeoServerRole> allRoles = getRoles();
		for (GeoServerRole existingRole : allRoles) {
			if (existingRole.getAuthority().equals(role)) {
				return new GeoServerRole(role);
			}
		}
		return null;
	}

	public GeoServerRole getParentRole(GeoServerRole role) throws IOException {
		return null;
	}

	public GeoServerRole getRoleByName(String role) throws IOException {
		return createRoleObject(role);
	}

	public void load() throws IOException {
		// No load roles loaded here since roles are loaded whenever required
		RoleLoadedEvent roleLoadedEvent = new RoleLoadedEvent(this);
		synchronized(listeners) {
			for (RoleLoadedListener listener : listeners) {
				listener.rolesChanged(roleLoadedEvent);
			}
		}
	}

	public Properties personalizeRoleParams(String roleName,
			Properties roleParams, String userName, Properties userProps)
			throws IOException {
		Properties merged = new Properties(roleParams);
		for (Entry<Object, Object> entry : userProps.entrySet()) {
			merged.put(entry.getKey(), entry.getValue());
		}
		return merged;
	}

	public GeoServerRole getAdminRole() {
		LOGGER.info("Admin Role is: " + adminRole);
		if (!StringUtils.hasLength(adminRole)) {
			return null;
		}
		try {
			return getRoleByName(adminRole);
		} catch (IOException e) {
			return null;
		}
	}

	public GeoServerRole getGroupAdminRole() {
		LOGGER.info("Group Admin Role is: " + groupAdminRole);
		if (!StringUtils.hasLength(groupAdminRole)) {
			return null;
		}
		try {
			return getRoleByName(groupAdminRole);
		} catch (IOException e) {
			return null;
		}
	}

	public int getRoleCount() throws IOException {
		return getRoles().size();
	}

	public Collection<? extends DataAccessRule> getLayerAccessRules(
			Catalog rawCatalog) throws IOException {
		LOGGER.info("Injected: loading layer rules from "
				+ getDrupalUserGroupServices().size() + " services");
		HashSet<DataAccessRule> rules = new HashSet<DataAccessRule>();
		for (DrupalUserGroupService service : getDrupalUserGroupServices()) {
			// Add workspace administrators
			HashSet<String> adminNames = new HashSet<String>();
			try {
				for (GeoServerRole admin : service.getWorkspaceAdministrators()) {
					adminNames.add(admin.getAuthority());
				}
			} catch (SQLException e) {
				throw new IOException(e);
			}
			rules.add(new DataAccessRule(service.getName(), "*",
					AccessMode.ADMIN, adminNames));

			// Add permissions that apply to single layers only
			HashSet<DataAccessRule> layerRules;
			try {
				layerRules = service.getLayerAccessRules(rawCatalog);
			} catch (SQLException e) {
				throw new IOException(e);
			}
			rules.addAll(layerRules);
		}
		return rules;
	}

	/**
	 * @return Administrators of at least one workspace
	 * @throws SQLException
	 */
	public HashMap<WorkspaceInfoImpl, Set<GeoServerRole>> getWorkspaceAdministrators()
			throws SQLException {
		HashMap<WorkspaceInfoImpl, Set<GeoServerRole>> workspaceAdmins = new HashMap<WorkspaceInfoImpl, Set<GeoServerRole>>();
		for (DrupalUserGroupService service : getDrupalUserGroupServices()) {
			WorkspaceInfoImpl workspace = new WorkspaceInfoImpl();
			workspace.setName(service.getName());
			workspaceAdmins
					.put(workspace, service.getWorkspaceAdministrators());
		}
		return workspaceAdmins;
	}
}
