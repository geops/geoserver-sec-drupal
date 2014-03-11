package org.cartaro.geoserver.security.drupal;

import java.io.InputStream;
import java.util.Scanner;

/**
 * class to access bundled resources
 * 
 * @author nico mandery
 *
 */
public class ExtensionInfo {
	
	private String getResourceContents(String resourceName) {
		InputStream rs = getClass().getResourceAsStream(resourceName);
		if (rs==null) {
			return "";
		}
		return new Scanner(rs,"UTF-8").useDelimiter("\\A").next().trim();
	}
	
	/**
	 * read the bundled git commit hash file
	 * 
	 * @return String containing the commit hash
	 */
	public String getGitVersion() {
		String gitVersion = getResourceContents("/geoserver-sec-drupal.gitversion");
		
		if ((gitVersion==null) || (gitVersion=="")) {
			gitVersion = "<No git version information available>";
		}
		return gitVersion;
	}
	

	/**
	 * read the version of the package/extension
	 * 
	 * @return String
	 */
	public String getVersion() {
		String version = getClass().getPackage().getImplementationVersion();
		if (version == null) {
			version = "unknown - not packaged";
		}
		return version;
	}
}
