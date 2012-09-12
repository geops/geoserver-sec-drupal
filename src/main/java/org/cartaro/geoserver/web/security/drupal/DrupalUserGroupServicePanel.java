package org.cartaro.geoserver.web.security.drupal;

import org.apache.wicket.markup.html.form.CheckBox;
import org.apache.wicket.markup.html.form.TextField;
import org.apache.wicket.model.IModel;
import org.cartaro.geoserver.security.drupal.DrupalSecurityServiceConfig;
import org.geoserver.security.web.usergroup.UserGroupServicePanel;

public class DrupalUserGroupServicePanel extends
		UserGroupServicePanel<DrupalSecurityServiceConfig> {

	/**
	 * 
	 */
	private static final long serialVersionUID = -3963597727535838770L;

	public DrupalUserGroupServicePanel(String id,
			IModel<DrupalSecurityServiceConfig> model) {
		super(id, model);
		add(new TextField<String>("databaseHost", String.class));
		add(new TextField<Integer>("databasePort", Integer.class));
		add(new TextField<String>("databaseName", String.class));
		add(new TextField<String>("databaseUser", String.class));
		add(new TextField<String>("databasePassword", String.class));
		add(new CheckBox("usePrefix"));
	}

}
