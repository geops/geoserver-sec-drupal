package org.cartaro.geoserver.web.security.drupal;

import org.apache.wicket.model.IModel;
import org.cartaro.geoserver.security.drupal.DrupalSecurityServiceConfig;
import org.geoserver.security.web.role.RoleServicePanel;

public class DrupalRoleServicePanel extends RoleServicePanel<DrupalSecurityServiceConfig>  {

	/**
	 * 
	 */
	private static final long serialVersionUID = 6616480488976286496L;

	public DrupalRoleServicePanel(String id,
			IModel<DrupalSecurityServiceConfig> model) {
		super(id, model);
	}

}
