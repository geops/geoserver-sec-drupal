package org.cartaro.geoserver.security.drupal;

import org.geoserver.config.util.XStreamPersister;
import org.geoserver.config.util.XStreamPersisterInitializer;

/**
 * @author Jan Vogt jan.vogt@geops.de.
 */
public class DrupalSecurityServiceConfigWhiteLister implements XStreamPersisterInitializer {
    @Override
    public void init(XStreamPersister persister) {
        persister.getXStream().allowTypes(new Class[]{
                DrupalSecurityServiceConfig.class
        });
    }
}
