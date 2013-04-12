package org.cartaro.geoserver.security.drupal;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.geoserver.config.impl.GeoServerLifecycleHandler;
import org.geoserver.platform.GeoServerExtensions;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.config.SecurityManagerConfig;
import org.geotools.util.logging.Logging;

/**
 * Reloads security configuration on call of /rest/reload.
 */
public class LifecycleHandler implements GeoServerLifecycleHandler {
	protected static Logger LOGGER = Logging
			.getLogger("org.geoserver.security");

	public void onReset() {
		LOGGER.info("LifecyleHandler resets.");
	}

	public void onDispose() {
		// Empty as no special handling of disposal needed.
	}

	public void onReload() {
		reloadSecurityConfiguration();
	}

	private void reloadSecurityConfiguration() {
		LOGGER.info("Reloading security configuration.");

		GeoServerSecurityManager securityManager = GeoServerExtensions
				.bean(GeoServerSecurityManager.class);

		try {
			// Load configuration from files so that those can be edited outwit
			// GeoServer.
			SecurityManagerConfig securityConfig = securityManager
					.loadSecurityConfig();
			try {
				// Use the configuration just read. Will rewrite the security
				// configuration files with the same content.
				securityManager.saveSecurityConfig(securityConfig);
			} catch (Exception e) {
				LOGGER.log(Level.WARNING,
						"Failed to rewrite security configuration.", e);
			}
		} catch (IOException e1) {
			LOGGER.log(Level.WARNING, "Failed to load security configuration.",
					e1);
		}
	}
}
