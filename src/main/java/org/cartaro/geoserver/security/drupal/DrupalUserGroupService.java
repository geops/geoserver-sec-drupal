package org.cartaro.geoserver.security.drupal;

import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.logging.Logger;

import org.geoserver.catalog.Catalog;
import org.geoserver.catalog.LayerInfo;
import org.geoserver.security.AccessMode;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.GeoServerUserGroupStore;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geoserver.security.event.UserGroupLoadedEvent;
import org.geoserver.security.event.UserGroupLoadedListener;
import org.geoserver.security.impl.AbstractGeoServerSecurityService;
import org.geoserver.security.impl.DataAccessRule;
import org.geoserver.security.impl.GeoServerRole;
import org.geoserver.security.impl.GeoServerUser;
import org.geoserver.security.impl.GeoServerUserGroup;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class DrupalUserGroupService extends AbstractGeoServerSecurityService
		implements GeoServerUserGroupService {
	protected static Logger LOGGER = org.geotools.util.logging.Logging.getLogger("org.geoserver.security");
	
	/**
	 * Role that is used to grant workspace-wide access during installation of a Drupal instance.
	 */
	private static final GeoServerRole INSTALLATION_ADMINISTRATOR = new GeoServerRole("INSTALLATION_ADMINISTRATOR");
	
	/**
	 * Denotes Drupal root users which are allowed to do everything. They have uid=1 in table users.
	 */
	private static final GeoServerRole DRUPAL_ROOT_ROLE = new GeoServerRole("administrator");
	
	private Set<UserGroupLoadedListener> listeners = Collections
			.synchronizedSet(new HashSet<UserGroupLoadedListener>());
	private DrupalDatabaseConnector connector;
	private String passwordEncoderName;
	private String passwordValidatorName;
	
	@Override
	public void initializeFromConfig(SecurityNamedServiceConfig config)
			throws IOException {
		super.initializeFromConfig(config);
		DrupalSecurityServiceConfig drupalConfig = (DrupalSecurityServiceConfig) config;
		passwordEncoderName = drupalConfig.getPasswordEncoderName();
		passwordValidatorName = drupalConfig.getPasswordPolicyName();
		try {
			connector = new DrupalDatabaseConnector(drupalConfig);
		} catch (ClassNotFoundException e) {
			throw new IOException(e);
		}
	}

	public UserDetails loadUserByUsername(String username)
			throws UsernameNotFoundException {
		return new GeoServerUser(username);
	}

	public GeoServerUserGroupStore createStore() throws IOException {
		return null;
	}

	public void registerUserGroupLoadedListener(UserGroupLoadedListener listener) {
		listeners.add(listener);
	}

	public void unregisterUserGroupLoadedListener(
			UserGroupLoadedListener listener) {
		listeners.remove(listener);
	}

	public GeoServerUserGroup getGroupByGroupname(String groupname)
			throws IOException {
		// Drupal does not support user groups
		return null;
	}

	public GeoServerUser getUserByUsername(String username) throws IOException {
		LOGGER.info("Drupal GroupService loads user");
		try {
			ResultSet rs = connector.getResultSet("select exists("
					+ "select true from users where name=?" + ") as exists",
					connector.stripInstancePrefix(username));
			rs.next();
			if (rs.getBoolean("exists")) {
				return new GeoServerUser(username);
			}
			return null;
		} catch (SQLException e) {
			throw new IOException(e);
		}
	}

	public GeoServerUser createUserObject(String username, String password,
			boolean isEnabled) throws IOException {
		return new GeoServerUser(username);
	}

	public GeoServerUserGroup createGroupObject(String groupname,
			boolean isEnabled) throws IOException {
		return new GeoServerUserGroup(groupname);
	}

	public SortedSet<GeoServerUser> getUsers() throws IOException {
		LOGGER.info("Drupal GroupService loads user list");
		TreeSet<GeoServerUser> users = new TreeSet<GeoServerUser>();
		try {
			ResultSet rs = connector.getResultSet("select name from users");
			while (rs.next()) {
				users.add(new GeoServerUser(connector.addInstancePrefix(rs
						.getString("name"))));
				HashSet<GrantedAuthority> roleset = new HashSet<GrantedAuthority>();
				roleset.add(new GeoServerRole("schreiber"));
				users.last().setAuthorities(roleset);
			}
			return Collections.unmodifiableSortedSet(users);
		} catch (SQLException e) {
			throw new IOException(e);
		}
	}

	public SortedSet<GeoServerUserGroup> getUserGroups() throws IOException {
		TreeSet<GeoServerUserGroup> set = new TreeSet<GeoServerUserGroup>();
		// Return empty collection since Drupal does not support user groups
		return Collections.unmodifiableSortedSet(set);
	}

	public SortedSet<GeoServerUser> getUsersForGroup(GeoServerUserGroup group)
			throws IOException {
		// Return empty collection since Drupal does not support user groups
		return Collections.unmodifiableSortedSet(new TreeSet<GeoServerUser>());
	}

	public SortedSet<GeoServerUserGroup> getGroupsForUser(GeoServerUser user)
			throws IOException {
		TreeSet<GeoServerUserGroup> set = new TreeSet<GeoServerUserGroup>();
		// Return empty collection since Drupal does not support user groups
		return Collections.unmodifiableSortedSet(set);
	}

	public void load() throws IOException {
		// No load roles loaded here since users are loaded whenever required
		UserGroupLoadedEvent event = new UserGroupLoadedEvent(this);
		for (UserGroupLoadedListener listener : listeners) {
			listener.usersAndGroupsChanged(event);
		}
	}

	public String getPasswordEncoderName() {
		return passwordEncoderName;
	}

	public String getPasswordValidatorName() {
		return passwordValidatorName;
	}

	public int getUserCount() throws IOException {
		ResultSet rs;
		try {
			rs = connector.getResultSet("select count(*) from users");
			rs.next();
			return rs.getInt("count");
		} catch (SQLException e) {
			throw new IOException(e);
		}
	}

	public int getGroupCount() throws IOException {
		// Drupal does not support groups
		return 0;
	}

	public SortedSet<String> getUserNamesForRole(GeoServerRole role)
			throws IOException {
		TreeSet<String> userNames = new TreeSet<String>();

		// Add all users of instance having the role
		ResultSet rs;
		try {
			rs = connector
					.getResultSet(
							"select users.name from users join users_roles using(uid) join role using(rid) where role.name =?",
							connector.stripInstancePrefix(role).getAuthority());
			while (rs.next()) {
				userNames
						.add(connector.addInstancePrefix(
								new GeoServerRole(rs.getString("name")))
								.getAuthority());
			}
			
			if(DRUPAL_ROOT_ROLE.equals(role)){
				// id=1 means administrative privileges in Drupal
				rs = connector.getResultSet("select name from users where uid=1");
				if(rs.next()){
					userNames.add(connector.addInstancePrefix(rs.getString("name")));
				}
			}
		} catch (SQLException e) {
			throw new IOException(e);
		}
		return Collections.unmodifiableSortedSet(userNames);
	}

	public SortedSet<GeoServerRole> getRolesForUser(String username)
			throws IOException {
		// Add role for instance user
		TreeSet<GeoServerRole> roles = new TreeSet<GeoServerRole>();
		try {
			ResultSet rs = connector
					.getResultSet(
							"select role.name from role join users_roles using(rid) join users using(uid) where users.name=?",
							connector.stripInstancePrefix(
									new GeoServerRole(username)).getAuthority());
			while (rs.next()) {
				roles.add(connector.addInstancePrefix(new GeoServerRole(rs
						.getString("name"))));
			}
			
			// Make all users workspace administrators during Drupal installation
			if(connector.isDrupalCurrentlyInstalling()){
				roles.add(connector.addInstancePrefix(INSTALLATION_ADMINISTRATOR));
			} else {
				// id=1 means administrative privileges in Drupal
				ResultSet rsAdmin = connector.getResultSet("select uid=1 as admin from users where name=?", connector.stripInstancePrefix(username));
				rsAdmin.next();
				if(rsAdmin.getBoolean("admin")){
					roles.add(connector.addInstancePrefix(DRUPAL_ROOT_ROLE));
				}
			}
		} catch (SQLException e) {
			throw new IOException(e);
		}
		return Collections.unmodifiableSortedSet(roles);
	}

	public SortedSet<GeoServerRole> getRoles() throws IOException {
		TreeSet<GeoServerRole> foundRoles = new TreeSet<GeoServerRole>();
		foundRoles.add(connector.addInstancePrefix(DRUPAL_ROOT_ROLE));
		
		ResultSet roles;
		try {
			roles = connector.getResultSet("select name from role");
			while (roles.next()) {
				foundRoles.add(connector.addInstancePrefix(new GeoServerRole(
						roles.getString("name"))));
			}
		} catch (SQLException e) {
			throw new IOException(e);
		}
		return Collections.unmodifiableSortedSet(foundRoles);
	}

	/**
	 * @return All users that have been granted the ‘Administer GeoServer’
	 *         privilege in Drupal
	 * @throws SQLException
	 */
	public SortedSet<GeoServerRole> getWorkspaceAdministrators()
			throws SQLException {
		ResultSet adminRoleNames = connector
				.getResultSet("select role.name "
						+ "from role_permission join role using(rid) "
						+ "where permission='administer geoserver' and module='geoserver'");

		TreeSet<GeoServerRole> foundRoles = new TreeSet<GeoServerRole>();
		while (adminRoleNames.next()) {
			foundRoles.add(connector.addInstancePrefix(new GeoServerRole(
					adminRoleNames.getString("name"))));
		}
		
		// Make a workspace administrator available during Drupal installation
		if(connector.isDrupalCurrentlyInstalling()){
			foundRoles.add(connector.addInstancePrefix(INSTALLATION_ADMINISTRATOR));
		}
		
		// Add Drupal root user
		foundRoles.add(connector.addInstancePrefix(DRUPAL_ROOT_ROLE));

		// Add global admin as admin since GeoServer assumes everybody is admin
		// when no admin was set
		foundRoles.add(GeoServerRole.ADMIN_ROLE);

		return Collections.unmodifiableSortedSet(foundRoles);
	}

	/**
	 * Build read and write rules for all layers in the workspace used by a Drupal instance
	 * @param rawCatalog
	 * @return Read and write access rules within workspace 
	 * @throws SQLException
	 */
	public HashSet<DataAccessRule> getLayerAccessRules(Catalog rawCatalog) throws SQLException {
		LOGGER.info("Injected: getLayerAccessRules");
		HashSet<DataAccessRule> layerAccessRules = new HashSet<DataAccessRule>();
		
		LOGGER.info("dumping catalog");
		for(LayerInfo layer: rawCatalog.getLayers()){
			String workspaceName =layer.getResource().getStore().getWorkspace().getName();
			LOGGER.info("workspacename "+workspaceName+"="+this.getName());
			if(workspaceName.equals(this.getName())){
				LOGGER.info(layer.getResource().getStore().getWorkspace().getName());
				LOGGER.info(layer.getName());
				String layerPermissionQuery = "select array_agg(role.name) as roles " +
						"from role " +
						"join role_permission using(rid) " +
						"where permission=? and module='geoserver' " +
						"having array_agg(role.name) is not null";
				
				ResultSet viewPermissions = connector.getResultSet(layerPermissionQuery, "read "+layer.getName());
				LOGGER.info("granting read permission for "+this.getName()+" "+layer.getName());
				while(viewPermissions.next()){
					layerAccessRules.add(buildDataAccessRule(layer.getName(),(String[]) viewPermissions.getArray("roles").getArray(), AccessMode.READ));
				}
				
				ResultSet createEditDeletePermissions = connector.getResultSet(layerPermissionQuery, "write "+layer.getName());
				LOGGER.info("granting write permission for "+this.getName()+" "+layer.getName());
				while(createEditDeletePermissions.next()){
					layerAccessRules.add(buildDataAccessRule(layer.getName(), (String[]) createEditDeletePermissions.getArray("roles").getArray(), AccessMode.WRITE));
				}
			}
		}

		return layerAccessRules;
	}

	/**
	 * Builds an access rule and adds instance prefix to all roles
	 * @param layerName
	 * @param roles
	 * @param mode
	 * @return
	 */
	private DataAccessRule buildDataAccessRule(String layerName, String[] roles,
			AccessMode mode) {
		HashSet<String> roleNames = new HashSet<String>();
		for (String roleName : roles) {
			LOGGER.info(" to "+connector.addInstancePrefix(roleName));
			roleNames.add(connector.addInstancePrefix(roleName));
		}
		return new DataAccessRule(this.getName(), layerName, mode, roleNames);
	}
}
