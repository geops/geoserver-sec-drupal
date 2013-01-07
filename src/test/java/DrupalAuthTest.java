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
		assertEquals("admin3", connector.stripInstancePrefix("i3_admin3"));
	}
	
	/**
	 * If prefixing is enabled, the prefix should be the instance name plus an underscore.
	 */
	@Test
	public void testPrefixing() {
		DrupalSecurityServiceConfig config = new DrupalSecurityServiceConfig();
		config.setName("test345");
		assertEquals("", config.getDrupalInstancePrefix());
		
		config.setUsePrefix(true);
		assertEquals("test345_", config.getDrupalInstancePrefix());
	}
}
