import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;
import org.cartaro.geoserver.security.drupal.DrupalAuthenticationProvider;
import org.cartaro.geoserver.security.drupal.DrupalSecurityServiceConfig;
import org.junit.Test;
import static org.junit.Assert.*;

public class DrupalPassword {

	@Test
	public void testPasswordBase64Encode() throws DecoderException {
		DrupalAuthenticationProvider drupalAuthenticationProvider = getConfig();
		String calculated;
		
		calculated = drupalAuthenticationProvider
				.drupalPasswordBase64Encode(Hex.decodeHex("1dd2e9d727482581f55375fd8823d79c0f65eda4d183288ff2e512e7f48faf6e41fbf9842a7b0a3dd385e2cdfd7b3d1751403c18d777e89261e47db1d9c60050".toCharArray()), 64);
		assertEquals("R6RuLT0GZ2MxHJLz6CmpQyENhHOo1WmXmLi2bHzXjuKEvbDVegb0xARVWrQzvpn3F/2DMQxRc9NMYrLgNPA.E/", calculated);
	}

	private DrupalAuthenticationProvider getConfig() {
		// There is no in-memory database so far, thus use local development database.
		// Any Drupal 7 database should work.
		DrupalSecurityServiceConfig config = new DrupalSecurityServiceConfig();
		config.setDatabaseHost("localhost");
		config.setDatabaseName("cartaro");
		config.setDatabasePort(5432);
		config.setDatabaseUser("drupal-7");
		config.setDatabasePassword("drupal-7");
		
		DrupalAuthenticationProvider drupalAuthenticationProvider = new DrupalAuthenticationProvider(
				config);
		return drupalAuthenticationProvider;
	}

	@Test
	public void testPasswordCrypt() throws SecurityException, NoSuchMethodException, IllegalArgumentException, IllegalAccessException, InvocationTargetException {
		DrupalAuthenticationProvider drupalAuthenticationProvider = getConfig();
		Method drupalPasswordCrypt = DrupalAuthenticationProvider.class.getDeclaredMethod("drupalPasswordCrypt", String.class, String.class, String.class);
		drupalPasswordCrypt.setAccessible(true);
		
		String calcHash = (String) drupalPasswordCrypt.invoke(drupalAuthenticationProvider, "SHA-512", "drupal-7.12", "$S$DYz5lF6quR6RuLT0GZ2MxHJLz6CmpQyENhHOo1WmXmLi2bHzXjuK");
		assertEquals("$S$DYz5lF6quR6RuLT0GZ2MxHJLz6CmpQyENhHOo1WmXmLi2bHzXjuK", calcHash);
	}
}