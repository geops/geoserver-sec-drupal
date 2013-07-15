package org.cartaro.geoserver.security.drupal.filter;

import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map.Entry;
import java.util.Set;
import java.util.Timer;
import java.util.logging.Logger;

import org.cartaro.geoserver.security.drupal.DrupalRoleService;
import org.geoserver.catalog.impl.WorkspaceInfoImpl;
import org.geoserver.config.GeoServerDataDirectory;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.GeoServerRoleService;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.RESTfulDefinitionSource;
import org.geoserver.security.RESTfulDefinitionSource.RESTfulDefinitionSourceMapping;
import org.geoserver.security.impl.GeoServerRole;
import org.geoserver.security.impl.RESTAccessRuleDAO;
import org.geotools.util.logging.Logging;
import org.springframework.security.access.SecurityConfig;

/**
 * Provides access rules for REST requests such that each instance administrator
 * is allowed to do anything with their workspaces and dependent objects.
 * However instance administrators are not allowed to access any URI that would
 * provide access to others' workspaces.
 */
public class DrupalRESTAccessRuleDAO extends RESTAccessRuleDAO implements LastModificationTriggerable {
	protected static Logger LOGGER = Logging
			.getLogger(DrupalRESTAccessRuleDAO.class);

	/**
	 * Should be the time of last modification of permission related data in
	 * Drupal. Currently, this is just a time set in intervals because the
	 * former is unknown.
	 */
	private long lastModified;

	public DrupalRESTAccessRuleDAO(GeoServerDataDirectory dd)
			throws IOException {
		super(dd);
		LOGGER.info("Drupal REST Access Rule injected");

		// Change modification date to force update of permissions every 5s.
		Timer modificationTrigger = new Timer();
		modificationTrigger.scheduleAtFixedRate(new LastModificationTimerTask(this), 2000, 2000);
	}

	/**
	 * Each rule gets parsed in {@link RESTfulDefinitionSource#processPathList}.
	 * Path is given by the string until the first colon or equals sign if no
	 * colon given in name. A comma-separated list of HTTP methods make up the
	 * remainder of the name. An equals sign splits name and value. Value is a
	 * comma-separated list.
	 */
	@Override
	public List<String> getRules() {
		final ArrayList<String> rules = new ArrayList<String>();
		// Deny all other request except for GeoServer's administrators.
		// Need to be set in order to block unwanted access!
		rules.add("/**:GET,POST,PUT,DELETE=ROLE_ADMINISTRATOR");

		assert rules.size() == 1 : "Excatly one rule must be provided as this triggers getRESTRules.";
		return rules;
	}

	/**
	 * @return Rules that grant instance administrators full access to their
	 *         workspaces whilst prohibiting to access others' data.
	 */
	public Collection<RESTfulDefinitionSourceMapping> getRESTRules() {
		ArrayList<RESTfulDefinitionSourceMapping> rules = new ArrayList<RESTfulDefinitionSourceMapping>();

		final GeoServerSecurityManager manager = GeoServerExtensions
				.bean(GeoServerSecurityManager.class);
		final GeoServerRoleService activeRoleService = manager
				.getActiveRoleService();
		if (activeRoleService instanceof DrupalRoleService) {
			// Grant Drupal instances access to REST services
			final DrupalRoleService roleService = (DrupalRoleService) activeRoleService;

			try {
				final HashMap<WorkspaceInfoImpl, Set<GeoServerRole>> admins = roleService
						.getWorkspaceAdministrators();
				final HashSet<GeoServerRole> sharedAdmins = new HashSet<GeoServerRole>();
				for (final Entry<WorkspaceInfoImpl, Set<GeoServerRole>> workspaceMapping : admins
						.entrySet()) {
					// Collect administrative roles for permission that span
					// across workspaces
					sharedAdmins.addAll(workspaceMapping.getValue());

					final String workspaceName = workspaceMapping.getKey()
							.getName();
					// Allow full access within own workspace
					final RESTfulDefinitionSourceMapping ruleWorkspacesSubs = new RESTfulDefinitionSourceMapping();
					ruleWorkspacesSubs.setUrl("/rest/workspaces/"
							+ workspaceName + "/**");
					// Allow to access own workspace in all formats
					final RESTfulDefinitionSourceMapping ruleWorkspaces = new RESTfulDefinitionSourceMapping();
					ruleWorkspaces.setUrl("/rest/workspaces/" + workspaceName
							+ ".*");
					// Allow full access to namespaces in own workspace
					final RESTfulDefinitionSourceMapping ruleNamespacesSubs = new RESTfulDefinitionSourceMapping();
					ruleNamespacesSubs.setUrl("/rest/namespaces/"
							+ workspaceName + "/**");
					// Allow to access own namespaces in all formats
					final RESTfulDefinitionSourceMapping ruleNamespaces = new RESTfulDefinitionSourceMapping();
					ruleNamespaces.setUrl("/rest/namespaces/" + workspaceName
							+ ".*");
					// Allow to access layers of own workspace in all formats
					final RESTfulDefinitionSourceMapping ruleLayers = new RESTfulDefinitionSourceMapping();
					ruleLayers.setUrl("/rest/layers/" + workspaceName + ":*");
					// Allow full access to layers of own workspace
					final RESTfulDefinitionSourceMapping ruleLayersSubs = new RESTfulDefinitionSourceMapping();
					ruleLayersSubs.setUrl("/rest/layers/" + workspaceName
							+ ":*/**");

					// Grant above permissions to all administrative users of
					// the workspace in question
					final RESTfulDefinitionSourceMapping[] workspaceDependedRules = {
							ruleWorkspacesSubs, ruleWorkspaces,
							ruleNamespacesSubs, ruleNamespaces, ruleLayers,
							ruleLayersSubs };
					for (final GeoServerRole workspaceAdmin : workspaceMapping
							.getValue()) {
						final SecurityConfig adminRole = new SecurityConfig(
								workspaceAdmin.getAuthority());
						for (final RESTfulDefinitionSourceMapping rule : workspaceDependedRules) {
							rule.addConfigAttribute(adminRole);
						}
					}
					for (final RESTfulDefinitionSourceMapping rule : workspaceDependedRules) {
						rules.add(rule);
					}
				}

				// Allow all workspace administrators to query the workspaces
				// and namespace list.
				final RESTfulDefinitionSourceMapping ruleWorkspacesShared = new RESTfulDefinitionSourceMapping();
				ruleWorkspacesShared.setUrl("/rest/workspaces*");
				ruleWorkspacesShared.setHttpMethods(new String[] { "GET",
						"POST" });
				final RESTfulDefinitionSourceMapping ruleNamespacesShared = new RESTfulDefinitionSourceMapping();
				ruleNamespacesShared.setUrl("/rest/namespaces*");
				ruleNamespacesShared.setHttpMethods(new String[] { "GET" });
				final RESTfulDefinitionSourceMapping aboutVersionShared = new RESTfulDefinitionSourceMapping();
				aboutVersionShared.setUrl("/rest/about/version*");
				aboutVersionShared.setHttpMethods(new String[] { "GET" });
				for (final GeoServerRole admin : sharedAdmins) {
					final SecurityConfig adminName = new SecurityConfig(
							admin.getAuthority());
					ruleWorkspacesShared.addConfigAttribute(adminName);
					ruleNamespacesShared.addConfigAttribute(adminName);
					aboutVersionShared.addConfigAttribute(adminName);
				}
				rules.add(ruleWorkspacesShared);
				rules.add(ruleNamespacesShared);
				rules.add(aboutVersionShared);
			} catch (SQLException e) {
				throw new RuntimeException(
						"Could not load workspace administrators", e);
			}
		}

		return rules;
	}

	@Override
	public long getLastModified() {
		return lastModified;
	}

	@Override
	public boolean isModified() {
		// Refresh always because there is currently no way for GeoServer to be
		// notified about changes in Drupal.
		return true;
	}

	public void setLastModified(long newLastModified) {
		lastModified = newLastModified;
	}
}
