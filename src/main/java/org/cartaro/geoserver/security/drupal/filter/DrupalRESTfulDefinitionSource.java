package org.cartaro.geoserver.security.drupal.filter;

import java.util.List;

import org.geoserver.security.RESTfulDefinitionSource;
import org.geoserver.security.impl.RESTAccessRuleDAO;

/**
 * Injects REST access roles without the need to serialize them first. This is
 * required to control access to URI that include colons for example since
 * GeoServers string based configuration cannot handle such cases.
 * 
 * Note that the injection via {@linkplain setMappings} is very hacky but there
 * is no other usable API in GeoServer 2.2.
 */
public class DrupalRESTfulDefinitionSource extends RESTfulDefinitionSource {
	/**
	 * Rule provider which should be the same reference as
	 * {@linkplain RESTfulDefinitionSource#dao}.
	 */
	private RESTAccessRuleDAO dao;

	public DrupalRESTfulDefinitionSource(RESTAccessRuleDAO dao) {
		super(dao);
		this.dao = dao;
	}
	
	/**
	 * Ensure GeoServer builds its rules for permission checks anew on next use.
	 */
	public void invalidateRulesCache(){
		this.dao.reload();
	}

	/**
	 * Adds to given mappings to be used for controlling access. Additionally
	 * adds the rules which are provided by
	 * {@linkplain DrupalRESTAccessRuleDAO#getRESTRules()}.
	 * 
	 * GeoServer does not seem to provide a better API currently to define rules
	 * without the need to provide them in serialized form. In order to avoid
	 * serializing objects just to deserialize them again and mainly because of
	 * not existent escaping this implementation is used. It is to be migrated
	 * to something better once the means in form of an API are there.
	 */
	public void setMappings(List<RESTfulDefinitionSourceMapping> mappings) {
		if (dao instanceof DrupalRESTAccessRuleDAO) {
			// Also add rules that don't depend on intermediate string
			// serialization
			DrupalRESTAccessRuleDAO drupalDao = (DrupalRESTAccessRuleDAO) dao;
			mappings.addAll(0, drupalDao.getRESTRules());
		}
		super.setMappings(mappings);
	}
}
