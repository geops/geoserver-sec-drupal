import static org.junit.Assert.assertEquals;

import org.cartaro.geoserver.security.drupal.DrupalDatabaseConnector;
import org.cartaro.geoserver.security.drupal.DrupalSecurityServiceConfig;
import org.junit.Test;


public class DrupalAuthTest {
	@Test
	public void stripPrefix() throws ClassNotFoundException{
		DrupalSecurityServiceConfig config = new DrupalSecurityServiceConfig();
		config.setUsePrefix(true);
		config.setName("i3");
		DrupalDatabaseConnector connector = new DrupalDatabaseConnector(config);
		assertEquals("admin3", connector.stripInstancePrefix("i3:admin3"));
	}
}
