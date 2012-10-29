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
import java.util.Timer;
import java.util.TimerTask;
import java.util.TreeSet;
import java.util.concurrent.ConcurrentHashMap;
import java.util.logging.Logger;

import org.geoserver.catalog.Catalog;
import org.geoserver.catalog.impl.WorkspaceInfoImpl;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.AccessMode;
import org.geoserver.security.GeoServerRoleService;
import org.geoserver.security.GeoServerRoleStore;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.event.RoleLoadedEvent;
import org.geoserver.security.event.RoleLoadedListener;
import org.geoserver.security.impl.DataAccessRule;
import org.geoserver.security.impl.GeoServerRole;
import org.geotools.util.logging.Logging;

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
	private List<DrupalUserGroupService> userGroupServices = new ArrayList<DrupalUserGroupService>();

	public void initializeFromConfig(SecurityNamedServiceConfig config)
			throws IOException {
		GeoServerSecurityManager manager = GeoServerExtensions
				.bean(GeoServerSecurityManager.class);
		List<GeoServerUserGroupService> allUserGroupServices = manager
				.loadUserGroupServices();
		for (GeoServerUserGroupService userGroupService : allUserGroupServices) {
			if (userGroupService instanceof DrupalUserGroupService) {
				DrupalUserGroupService drupalUserGroupService = (DrupalUserGroupService) userGroupService;
				userGroupServices.add(drupalUserGroupService);
			}
		}
		LOGGER.info("Merging Drupal role services: " + userGroupServices.size());
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
		listeners.add(listener);
	}

	public void unregisterRoleLoadedListener(RoleLoadedListener listener) {
		listeners.remove(listener);
	}

	public SortedSet<String> getGroupNamesForRole(GeoServerRole role)
			throws IOException {
		// Drupal does not support groups so set is always empty
		return Collections.unmodifiableSortedSet(new TreeSet<String>());
	}

	public SortedSet<String> getUserNamesForRole(GeoServerRole role)
			throws IOException {
		TreeSet<String> userNames = new TreeSet<String>();
		for (DrupalUserGroupService service : userGroupServices) {
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
		for (DrupalUserGroupService service : userGroupServices) {
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
		for (DrupalUserGroupService service : userGroupServices) {
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
		for (RoleLoadedListener listener : listeners) {
			listener.rolesChanged(roleLoadedEvent);
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
		// There is no admin role since multiple Drupal installation might share
		// the same GeoServer
		return null;
	}

	public GeoServerRole getGroupAdminRole() {
		// There is no admin role since multiple Drupal installation might share
		// the same GeoServer
		return null;
	}

	public int getRoleCount() throws IOException {
		return getRoles().size();
	}

	public Collection<? extends DataAccessRule> getLayerAccessRules(Catalog rawCatalog) throws IOException {
		LOGGER.info("Injected: loading layer rules from "+userGroupServices.size()+" services");
		HashSet<DataAccessRule> rules = new HashSet<DataAccessRule>();
		for (DrupalUserGroupService service : userGroupServices) {
			// Add workspace administrators
			HashSet<String> adminNames = new HashSet<String>();			
			try {
				for(GeoServerRole admin:service.getWorkspaceAdministrators()){
					adminNames.add(admin.getAuthority());
				}
			} catch (SQLException e) {
				throw new IOException(e);
			}
			rules.add(new DataAccessRule(service.getName(), "*", AccessMode.ADMIN, adminNames));
			
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
	public HashMap<WorkspaceInfoImpl,Set<GeoServerRole>> getWorkspaceAdministrators() throws SQLException {
		HashMap<WorkspaceInfoImpl, Set<GeoServerRole>> workspaceAdmins = new HashMap<WorkspaceInfoImpl, Set<GeoServerRole>>();
		for (DrupalUserGroupService service : userGroupServices) {
			WorkspaceInfoImpl workspace = new WorkspaceInfoImpl();
			workspace.setName(service.getName());
			workspaceAdmins.put(workspace, service.getWorkspaceAdministrators());
		}
		return workspaceAdmins;
	}
}
