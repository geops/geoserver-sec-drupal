package org.cartaro.geoserver.web.security.drupal;

import org.cartaro.geoserver.security.drupal.DrupalRoleService;
import org.cartaro.geoserver.security.drupal.DrupalSecurityServiceConfig;
import org.geoserver.security.web.role.RoleServicePanelInfo;

public class DrupalRoleServicePanelInfo extends RoleServicePanelInfo<DrupalSecurityServiceConfig, DrupalRoleServicePanel> {


	/**
	 * 
	 */
	private static final long serialVersionUID = -3971641286599379457L;

	public DrupalRoleServicePanelInfo() {
        setComponentClass(DrupalRoleServicePanel.class);
        setServiceClass(DrupalRoleService.class);
        setServiceConfigClass(DrupalSecurityServiceConfig.class);
    }

}
