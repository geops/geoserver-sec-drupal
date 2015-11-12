package org.cartaro.geoserver.security.drupal;

import java.io.IOException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.logging.Logger;

import org.geoserver.catalog.Catalog;
import org.geoserver.catalog.LayerInfo;
import org.geoserver.config.GeoServer;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.*;
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

	/**
	 * Denotes user having the permission to administer geoserver from the geoserver plugin.
	 */
	private static final GeoServerRole DRUPAL_ADMINISTER_GEOSERVER_ROLE = new GeoServerRole("GeoServer Administrators");
	
	/**
	 * Role name for all authenticated users in Drupal.
	 */
	private static final String AUTHENTICATED_USER = "authenticated user";
	
	/**
	 * Role name for all non-authenticated users in Drupal.
	 */
	private static final String ANONYMOUS_USER = "anonymous user";
	
	private Set<UserGroupLoadedListener> listeners = Collections
			.synchronizedSet(new HashSet<UserGroupLoadedListener>());
	private DrupalDatabaseConnector connector;
	private String passwordEncoderName;
	private String passwordValidatorName;
	
	private enum PropertyQueryOperator {
		HAS_PROPERTY,
		NOT_HAS_PROPERTY
	};
	
	@Override
	public void initializeFromConfig(SecurityNamedServiceConfig config)
			throws IOException {
		super.initializeFromConfig(config);
		DrupalSecurityServiceConfig drupalConfig = (DrupalSecurityServiceConfig) config;
		passwordEncoderName = drupalConfig.getPasswordEncoderName();
		passwordValidatorName = drupalConfig.getPasswordPolicyName();

		if(connector!=null){
			connector.close();
		}
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
		synchronized(listeners) {
			listeners.add(listener);
		}
	}

	public void unregisterUserGroupLoadedListener(
			UserGroupLoadedListener listener) {
		synchronized(listeners) {
			listeners.remove(listener);
		}
	}

	public GeoServerUserGroup getGroupByGroupname(String groupname)
			throws IOException {
		// Drupal does not support user groups
		return null;
	}

	public GeoServerUser getUserByUsername(String username) throws IOException {
		LOGGER.info("Drupal GroupService loads user");
		try {
			connector.connect();
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
		} finally {
			connector.disconnect();
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
			connector.connect();
			ResultSet rs = connector.getResultSet("select name from users");
			while (rs.next()) {
				users.add(new GeoServerUser(connector.addInstancePrefix(rs
						.getString("name"))));
				HashSet<GrantedAuthority> roleset = new HashSet<GrantedAuthority>();
				roleset.add(new GeoServerRole("schreiber")); // TODO: why is this needed. does the set just need at least one role
				users.last().setAuthorities(roleset);
			}
			return Collections.unmodifiableSortedSet(users);
		} catch (SQLException e) {
			throw new IOException(e);
		} finally {
			connector.disconnect();
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
		synchronized(listeners) {
			for (UserGroupLoadedListener listener : listeners) {
				listener.usersAndGroupsChanged(event);
			}
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
			connector.connect();
			rs = connector.getResultSet("select count(*) from users");
			rs.next();
			return rs.getInt("count");
		} catch (SQLException e) {
			throw new IOException(e);
		} finally {
			connector.disconnect();
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
			connector.connect();
			final GeoServerRole stripedRole = connector.stripInstancePrefix(role);
			if (DRUPAL_ROOT_ROLE.equals(stripedRole)) {
				// id=1 means administrative privileges in Drupal
				rs = connector.getResultSet("select name from users where uid=1");
				if(rs.next()){
					userNames.add(connector.addInstancePrefix(rs.getString("name")));
				}
				rs = null;
			} else if (DRUPAL_ADMINISTER_GEOSERVER_ROLE.equals(stripedRole)) {
				rs = connector
						.getResultSet(
								"select distinct users.name from users " +
								"left join users_roles using(uid) " +
								"join role ON role.rid = users_roles.rid or role.name='authenticated user' " +
								"join role_permission rp on role.rid = rp.rid " +
								"where rp.permission = 'administer geoserver' and rp.module = 'geoserver'");

			} else {
				rs = connector
						.getResultSet(
								"select users.name from users join users_roles using(uid) join role using(rid) where role.name =?",
								stripedRole.getAuthority());
			}
			while (rs.next()) {
				userNames
						.add(connector.addInstancePrefix(
								new GeoServerRole(rs.getString("name")))
								.getAuthority());
			}
		} catch (SQLException e) {
			throw new IOException(e);
		} finally {
			connector.disconnect();
		}
		return Collections.unmodifiableSortedSet(userNames);
	}

	public SortedSet<GeoServerRole> getRolesForUser(String username)
			throws IOException {
		// Add role for instance user
		TreeSet<GeoServerRole> roles = new TreeSet<GeoServerRole>();
		try {
			connector.connect();
			ResultSet rs = connector
					.getResultSet(
							"select role.name from role join users_roles using(rid) join " +
							"users using(uid) where users.name=?",
							connector.stripInstancePrefix(
									new GeoServerRole(username)).getAuthority());
			while (rs.next()) {
				roles.add(connector.addInstancePrefix(new GeoServerRole(rs
						.getString("name"))));
			}
			rs = connector
					.getResultSet(
							"select exists(select * from users " +
									"left join users_roles using(uid) " +
									"join role ON role.rid = users_roles.rid or role.name='" + AUTHENTICATED_USER + "' " +
									"join role_permission rp on role.rid = rp.rid " +
									"where users.name=? and " +
									"rp.permission = 'administer geoserver' " +
									"and rp.module = 'geoserver') as admin",
							connector.stripInstancePrefix(
									new GeoServerRole(username)).getAuthority());
			if (rs.next() && rs.getBoolean("admin")) {
				roles.add(connector.addInstancePrefix(DRUPAL_ADMINISTER_GEOSERVER_ROLE));
			}
			// Make all users workspace administrators during Drupal installation
			if(connector.isDrupalCurrentlyInstalling()){
				roles.add(connector.addInstancePrefix(INSTALLATION_ADMINISTRATOR));
			} else {
				// id=1 means administrative privileges in Drupal
				ResultSet rsAdmin = connector.getResultSet("select uid=1 as admin from users where name=?", connector.stripInstancePrefix(username));
				if(rsAdmin.next() && rsAdmin.getBoolean("admin")){
					roles.add(connector.addInstancePrefix(DRUPAL_ROOT_ROLE));
				}
			}
			
			// Assign all known users the permissions of being authenticated and anonymous.
			roles.add(new GeoServerRole(connector.addInstancePrefix(AUTHENTICATED_USER)));
			roles.add(new GeoServerRole(connector.addInstancePrefix(ANONYMOUS_USER)));
		} catch (SQLException e) {
			throw new IOException(e);
		} finally {
			connector.disconnect();
		}
		// Add GeoServer Admin Roles if local Admin Roles are contained. See http://docs.geoserver.org/latest/en/user/security/usergrouprole/interaction.html
		// this is usually done by org.geoserver.security.impl.RoleCalculator::addMappedSystemRoles() which is not used.
		final GeoServerRoleService rs = GeoServerExtensions.bean(GeoServerSecurityManager.class).getActiveRoleService();
		if (roles.contains(rs.getAdminRole())) {
			roles.add(GeoServerRole.ADMIN_ROLE);
		}
		if (roles.contains(rs.getAdminRole())) {
			roles.add(GeoServerRole.GROUP_ADMIN_ROLE);
		}
		return Collections.unmodifiableSortedSet(roles);
	}

	public SortedSet<GeoServerRole> getRoles() throws IOException {
		TreeSet<GeoServerRole> foundRoles = new TreeSet<GeoServerRole>();
		foundRoles.add(connector.addInstancePrefix(DRUPAL_ROOT_ROLE));
		foundRoles.add(connector.addInstancePrefix(DRUPAL_ADMINISTER_GEOSERVER_ROLE));

		ResultSet roles;
		try {
			connector.connect();
			roles = connector.getResultSet("select name from role");
			while (roles.next()) {
				foundRoles.add(connector.addInstancePrefix(new GeoServerRole(
						roles.getString("name"))));
			}
		} catch (SQLException e) {
			throw new IOException(e);
		} catch (NullPointerException e){
			// Ignore missing connection here and return empty user list.
			// Keeps service editable in GUI despite wrongly configured connections.
			// Wrong configurations have been logged by failing connection acquire already.
		} finally {
			connector.disconnect();
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
		SortedSet<GeoServerRole> administrators;
		
		try {
			connector.connect();
			final ResultSet adminRoleNames = connector
					.getResultSet("select role.name "
							+ "from role_permission join role using(rid) "
							+ "where permission='administer geoserver' and module='geoserver'");
	
			final TreeSet<GeoServerRole> foundRoles = new TreeSet<GeoServerRole>();
			while (adminRoleNames.next()) {
				final String drupalRole = adminRoleNames.getString("name");
				if(drupalRole.equals(ANONYMOUS_USER)){
					// Let everybody administer because Drupal settings grant this for everybody.
					foundRoles.clear();
					return Collections.unmodifiableSortedSet(foundRoles);
				}
				foundRoles.add(connector.addInstancePrefix(new GeoServerRole(
						drupalRole)));
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
	
			administrators = Collections.unmodifiableSortedSet(foundRoles);
		} finally {
			connector.disconnect();
		}
		return administrators;
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
		
		try {
			LOGGER.info("dumping catalog");
			connector.connect();
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
					
					ResultSet viewPermissions = connector.getResultSet(layerPermissionQuery, "read layer "+layer.getName());
					LOGGER.info("granting read permission for "+this.getName()+" "+layer.getName());
					while(viewPermissions.next()){
						layerAccessRules.add(buildDataAccessRule(layer, (String[]) viewPermissions.getArray("roles").getArray(), AccessMode.READ));
					}
					
					ResultSet createEditDeletePermissions = connector.getResultSet(layerPermissionQuery, "write layer "+layer.getName());
					LOGGER.info("granting write permission for "+this.getName()+" "+layer.getName());
					while(createEditDeletePermissions.next()){
						layerAccessRules.add(buildDataAccessRule(layer, (String[]) createEditDeletePermissions.getArray("roles").getArray(), AccessMode.WRITE));
					}
				}
			}
		} finally {
			connector.disconnect();
		}

		return layerAccessRules;
	}

	/**
	 * Builds an access rule and adds instance prefix to all roles
	 * @param layer GeoServer layer
	 * @param roles Drupal role names
	 * @param mode
	 * @return
	 */
	private DataAccessRule buildDataAccessRule(final LayerInfo layer, final String[] roles,
			final AccessMode mode) {
		final HashSet<String> roleNames = new HashSet<String>();
		if(Arrays.asList(roles).contains(ANONYMOUS_USER)){
			// All access for everybody even not logged in users.
			roleNames.add("*");
		} else {
			for (final String roleName : roles) {
				LOGGER.info(" to "+connector.addInstancePrefix(roleName));
				roleNames.add(connector.addInstancePrefix(roleName));
			}
		}
		return new DataAccessRule(this.getName(), layer.getName(), mode, roleNames);
	}
	
	/**
	 * @param username
	 * @return True if this instance provided the user and is thus responsible for determining its roles.
	 */
	public boolean isResponsibleForUser(String username){
		return connector.hasInstancePrefix(username);
	}


	/**
	 * maps properties to columns of drupals "users" table.
	 * 
	 * @param propname
	 * @return The column of drupals "users"-table which holds the info for this property 
	 */
	private String getSQLPropertyColumn(String propname) {
		String columnName = null;
		if (propname=="mail") {
			columnName="mail";
		} else {
			columnName=null;
		}
		return columnName;
	}

	
	/**
	 * return users having or not having a property
	 * 
	 * @param propname
	 * @param propop
	 * @return
	 * @throws IOException
	 */
	private SortedSet<GeoServerUser> queryUserProperty(String propname, PropertyQueryOperator propop) 
				throws IOException {
		TreeSet<GeoServerUser> users = new TreeSet<GeoServerUser>();
		String columnName = getSQLPropertyColumn(propname);

		if (columnName != null) {
			try {
				LOGGER.info("quering catalog for property " + propname);
				connector.connect();
				
				String query = "select name from users where " + columnName + " ";
				if (propop==PropertyQueryOperator.HAS_PROPERTY) {
					query += "is not null and " + columnName + "is distinct from ''";
				}
				else if (propop==PropertyQueryOperator.NOT_HAS_PROPERTY) {
					query += "is null or " + columnName + " is not distinct from ''";
				}
				else {
					throw new IOException("Unsupported PropertyQueryOperator: " + propop.name());
				}
				
				ResultSet rs = connector.getResultSet(query);
				while (rs.next()) {
					users.add(new GeoServerUser(connector.addInstancePrefix(rs
							.getString("name"))));
					HashSet<GrantedAuthority> roleset = new HashSet<GrantedAuthority>();
					roleset.add(new GeoServerRole("schreiber")); // TODO: why is this needed. does the set just need at least one role
					users.last().setAuthorities(roleset);
				}
			} catch (SQLException e) {
				throw new IOException(e);
			} finally {
				connector.disconnect();
			}
		}
		return Collections.unmodifiableSortedSet(users);
	}
	
	/**
	 * return users which have a property with the given name and value
	 * 
	 * @param propname
	 * @param propvalue
	 * @return
	 * @throws IOException
	 */
	private SortedSet<GeoServerUser> queryUserPropertyByMatchingValue(String propname, String propvalue) 
			throws IOException {
		TreeSet<GeoServerUser> users = new TreeSet<GeoServerUser>();
		String columnName = getSQLPropertyColumn(propname);

		if (columnName != null) {
			try {
				LOGGER.info("quering catalog for property " + propname + " and value " + propvalue);
				connector.connect();
				
				String query = "select name from users where " + columnName + " is not distinct from ?";
				ResultSet rs = connector.getResultSet(query, propvalue);
				while (rs.next()) {
					users.add(new GeoServerUser(connector.addInstancePrefix(rs
							.getString("name"))));
					HashSet<GrantedAuthority> roleset = new HashSet<GrantedAuthority>();
					roleset.add(new GeoServerRole("schreiber")); // TODO: why is this needed. does the set just need at least one role
					users.last().setAuthorities(roleset);
				}		
			} catch (SQLException e) {
				throw new IOException(e);
			} finally {
				connector.disconnect();
			}
		}
		return Collections.unmodifiableSortedSet(users);
	}
	
	/**
	 * Added in http://jira.codehaus.org/browse/GEOS-5557.
	 */
	public SortedSet<GeoServerUser> getUsersHavingProperty(String propname)
			throws IOException {
		return queryUserProperty(propname, PropertyQueryOperator.HAS_PROPERTY);
	}

	/**
	 * Added in http://jira.codehaus.org/browse/GEOS-5557.
	 */
	public int getUserCountHavingProperty(String propname) throws IOException {
		SortedSet<GeoServerUser> users = getUsersHavingProperty(propname);
		if (users == null) {
			return 0;
		}
		return users.size();
	}

	/**
	 * Added in http://jira.codehaus.org/browse/GEOS-5557.
	 */
	public SortedSet<GeoServerUser> getUsersNotHavingProperty(String propname)
			throws IOException {
		return queryUserProperty(propname, PropertyQueryOperator.NOT_HAS_PROPERTY);
	}
	
	/**
	 * Added in http://jira.codehaus.org/browse/GEOS-5557.
	 * 
	 * Not really supported by this module so far as this method
	 * directly depends on getUsersNotHavingProperty.
	 */
	public int getUserCountNotHavingProperty(String propname)
			throws IOException {
		SortedSet<GeoServerUser> users = getUsersNotHavingProperty(propname);
		if (users == null) {
			return 0;
		}
		return users.size();
	}
	
	/**
	 * Added in http://jira.codehaus.org/browse/GEOS-5557.
	 */
	public SortedSet<GeoServerUser> getUsersHavingPropertyValue(
			String propname, String propvalue) throws IOException {
		return queryUserPropertyByMatchingValue(propname, propvalue);
	}
	
	/**
	 * Added in http://jira.codehaus.org/browse/GEOS-5557.
	 */
	public int getUserCountHavingPropertyValue(String propname, String propvalue)
			throws IOException {
		SortedSet<GeoServerUser> users = getUsersHavingPropertyValue(propname, propvalue);
		if (users == null) {
			return 0;
		}
		return users.size();
	}
}
