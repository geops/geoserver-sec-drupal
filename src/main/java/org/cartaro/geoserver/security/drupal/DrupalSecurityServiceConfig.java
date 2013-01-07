package org.cartaro.geoserver.security.drupal;

import org.geoserver.security.config.BaseSecurityNamedServiceConfig;
import org.geoserver.security.config.SecurityAuthProviderConfig;
import org.geoserver.security.config.SecurityRoleServiceConfig;
import org.geoserver.security.config.SecurityUserGroupServiceConfig;

public class DrupalSecurityServiceConfig extends BaseSecurityNamedServiceConfig
		implements SecurityAuthProviderConfig, SecurityRoleServiceConfig,
		SecurityUserGroupServiceConfig {

	private static final long serialVersionUID = 629956674199530104L;

	private String databaseHost = "localhost";
	private Integer databasePort = 5432;

	/**
	 * Flag to indicate if user names should be prefixed with the configuration
	 * name that provided them. Set to true to share a single GeoServer instance
	 * with other accessors.
	 */
	private boolean usePrefix = false;

	public Integer getDatabasePort() {
		return databasePort;
	}

	public void setDatabasePort(Integer databasePort) {
		this.databasePort = databasePort;
	}

	public String getDatabaseName() {
		return databaseName;
	}

	public void setDatabaseName(String databaseName) {
		this.databaseName = databaseName;
	}

	public String getDatabaseUser() {
		return databaseUser;
	}

	public void setDatabaseUser(String databaseUser) {
		this.databaseUser = databaseUser;
	}

	public String getDatabasePassword() {
		return databasePassword;
	}

	public void setDatabasePassword(String databasePassword) {
		this.databasePassword = databasePassword;
	}

	private String databaseName = "";

	/**
	 * Drupal user that is used for authentication checks. It is therefore
	 * required that this user can read user and role related tables.
	 */
	private String databaseUser = "";

	private String databasePassword = "";

	private String userGroupServiceName;

	public String getUserGroupServiceName() {
		return userGroupServiceName;
	}

	public void setUserGroupServiceName(String userGroupServiceName) {
		this.userGroupServiceName = userGroupServiceName;
	}

	public String getDatabaseHost() {
		return databaseHost;
	}

	public void setDatabaseHost(String databaseHost) {
		this.databaseHost = databaseHost;
	}

	public String getAdminRoleName() {
		// There are no admins
		return null;
	}

	public void setAdminRoleName(String adminRoleName) {
		// There are no admins
	}

	public String getGroupAdminRoleName() {
		// There are no admins
		return null;
	}

	public void setGroupAdminRoleName(String adminRoleName) {
		// There are no admins
	}

	private String passwordEncoderName;

	public String getPasswordEncoderName() {
		return passwordEncoderName;
	}

	public void setPasswordEncoderName(String passwordEncoderName) {
		this.passwordEncoderName = passwordEncoderName;
	}

	private String passwordPolicyName;

	public String getPasswordPolicyName() {
		return passwordPolicyName;
	}

	public void setPasswordPolicyName(String passwordPolicyName) {
		this.passwordPolicyName = passwordPolicyName;
	}

	/**
	 * @return Prefix for roles and users that ensures those objects are unique
	 *         within GeoServer across Drupal instances.
	 */
	public String getDrupalInstancePrefix() {
		if (isUsePrefix()) {
			return getName() +
					// Add separator so that user has an indication where instance ends and user name starts
					"_";
		}
		return "";
	}

	public boolean isUsePrefix() {
		return usePrefix;
	}

	public void setUsePrefix(boolean usePrefix) {
		this.usePrefix = usePrefix;
	}

}
