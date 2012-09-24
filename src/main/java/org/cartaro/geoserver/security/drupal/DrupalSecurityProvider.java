package org.cartaro.geoserver.security.drupal;

import java.io.IOException;
import java.util.logging.Logger;

import org.geoserver.config.util.XStreamPersister;
import org.geoserver.security.GeoServerAuthenticationProvider;
import org.geoserver.security.GeoServerRoleService;
import org.geoserver.security.GeoServerSecurityManager;
import org.geoserver.security.GeoServerSecurityProvider;
import org.geoserver.security.GeoServerUserGroupService;
import org.geoserver.security.config.SecurityNamedServiceConfig;
import org.geotools.util.logging.Logging;

public class DrupalSecurityProvider extends GeoServerSecurityProvider {

    static final Logger LOGGER = Logging.getLogger("org.geoserver.security");

    GeoServerSecurityManager securityManager;

    public DrupalSecurityProvider(GeoServerSecurityManager securityManager) {
        this.securityManager = securityManager;
    }
    
    @Override
    public void init(GeoServerSecurityManager manager) {
    	super.init(manager);
    	LOGGER.info("drupal init DrupalSecurityProvider");
    }

    @Override
    public void configure(XStreamPersister xp) {
        xp.getXStream().alias("drupal", DrupalSecurityServiceConfig.class);
    }

    @Override
    public Class<DrupalAuthenticationProvider> getAuthenticationProviderClass() {
    	LOGGER.info("get Drupal Auth provider class");
        return DrupalAuthenticationProvider.class;
    }
    
    @Override
    public GeoServerAuthenticationProvider createAuthenticationProvider(SecurityNamedServiceConfig config) {
    	LOGGER.info("Create Drupal Auth provider");
        return new DrupalAuthenticationProvider((DrupalSecurityServiceConfig)config);
    }
    
    @Override
    public Class<? extends GeoServerRoleService> getRoleServiceClass() {
        return DrupalRoleService.class; 
    }

    @Override
    public GeoServerRoleService createRoleService(SecurityNamedServiceConfig config)
            throws IOException {
    	LOGGER.info("Drupal config:"+config.getClassName());
        return new DrupalRoleService();
    }
    
    @Override
    public Class<? extends GeoServerUserGroupService> getUserGroupServiceClass() {
    	return DrupalUserGroupService.class;
    }
    
    @Override
    public GeoServerUserGroupService createUserGroupService(
    		SecurityNamedServiceConfig config) throws IOException {
    	LOGGER.info("Create DrupalUserGroupService");
    	return new DrupalUserGroupService();
    }
}