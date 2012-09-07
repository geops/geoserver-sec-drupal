package org.cartaro.geoserver.web.security.drupal;

import org.cartaro.geoserver.security.drupal.DrupalSecurityServiceConfig;
import org.cartaro.geoserver.security.drupal.DrupalUserGroupService;
import org.geoserver.security.web.usergroup.UserGroupServicePanelInfo;

public class DrupalUserGroupServicePanelInfo extends UserGroupServicePanelInfo<DrupalSecurityServiceConfig, DrupalUserGroupServicePanel> {

    /**
	 * 
	 */
	private static final long serialVersionUID = -2668003696706609472L;

	public DrupalUserGroupServicePanelInfo() {
        setComponentClass(DrupalUserGroupServicePanel.class);
        setServiceClass(DrupalUserGroupService.class);
        setServiceConfigClass(DrupalSecurityServiceConfig.class);
    }
}
