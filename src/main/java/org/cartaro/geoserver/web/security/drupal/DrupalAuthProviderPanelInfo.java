package org.cartaro.geoserver.web.security.drupal;

import org.cartaro.geoserver.security.drupal.DrupalAuthenticationProvider;
import org.cartaro.geoserver.security.drupal.DrupalSecurityServiceConfig;
import org.geoserver.security.web.auth.AuthenticationProviderPanelInfo;

public class DrupalAuthProviderPanelInfo
		extends
		AuthenticationProviderPanelInfo<DrupalSecurityServiceConfig, DrupalAuthProviderPanel> {

	/**
	 * 
	 */
	private static final long serialVersionUID = -812609575120792771L;

	public DrupalAuthProviderPanelInfo() {
		setComponentClass(DrupalAuthProviderPanel.class);
		setServiceClass(DrupalAuthenticationProvider.class);
		setServiceConfigClass(DrupalSecurityServiceConfig.class);
	}
}
