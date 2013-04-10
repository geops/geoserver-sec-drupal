package org.cartaro.geoserver.security.drupal;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.SortedSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.codec.binary.Hex;
import org.geoserver.security.GeoServerAuthenticationProvider;
import org.geoserver.security.impl.GeoServerRole;
import org.geotools.util.logging.Logging;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

/**
 * Verifies credentials based on a Drupal database.
 */
public class DrupalAuthenticationProvider extends
		GeoServerAuthenticationProvider {
	protected static Logger LOGGER = Logging
			.getLogger("org.geoserver.security");

	private static final int DRUPAL_HASH_LENGTH = 55;
	private DrupalDatabaseConnector connector;
	private DrupalUserGroupService userGroupService;

	public DrupalAuthenticationProvider() {
		userGroupService = new DrupalUserGroupService();
	}

	@Override
	public void initializeFromConfig(
			org.geoserver.security.config.SecurityNamedServiceConfig config)
			throws IOException {
		LOGGER.info("Reloading configuration " + config.getName());

		if (connector != null) {
			connector.close();
		}
		try {
			connector = new DrupalDatabaseConnector(
					(DrupalSecurityServiceConfig) config);
		} catch (ClassNotFoundException e) {
			throw new RuntimeException("Cannot find credential store for "
					+ config.getName());
		}

		try {
			userGroupService.initializeFromConfig(config);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

	@Override
	public boolean supports(Class<? extends Object> authentication,
			HttpServletRequest request) {
		LOGGER.finer("drupal support request");
		return Authentication.class.isAssignableFrom(authentication);
	}

	@Override
	public Authentication authenticate(Authentication authentication,
			HttpServletRequest request) {

		final UsernamePasswordAuthenticationToken token = (UsernamePasswordAuthenticationToken) authentication;

		LOGGER.info("Drupal user tries to log in:" + token.getPrincipal()
				+ " pw:" + token.getCredentials());
		try {
			final Object passwordRaw = token.getCredentials();
			// Trim whitespace from the password because Drupal does this, too.
			final String password = ((String) (passwordRaw == null ? ""
					: passwordRaw)).trim();
			
			String drupalUserName;
			try {
				drupalUserName = connector.stripInstancePrefix(token
						.getPrincipal().toString());
				LOGGER.info("Stripped user name: " + drupalUserName);
			} catch (IllegalArgumentException e) {
				// Prefix mismatch. State that this instance is not responsible
				// for authenticating user.
				return null;
			}
			boolean credentialsValid;

			boolean drupalCurrentlyInstalling = connector
					.isDrupalCurrentlyInstalling();
			LOGGER.info("Drupal currently installing:"
					+ drupalCurrentlyInstalling);

			if (drupalCurrentlyInstalling) {
				// Grant access to any Drupal instances that are currently being
				// installed
				credentialsValid = true;
			} else {
				ResultSet rs = connector.getResultSet(
						"select pass from users where name=? and status=1",
						drupalUserName);
				boolean userFound = rs.next();
				if (userFound == false) {
					LOGGER.info("User not found in Drupal database: "
							+ drupalUserName);
					// User name is not in Drupal database
					return null;
				}
				String passwordHash = rs.getString("pass");
				credentialsValid = drupalUserCheckPassword((String) password,
						passwordHash);
			}
			if (credentialsValid) {
				LOGGER.info("User " + token.getPrincipal() + " authorized");

				// Authorize user by setting its roles
				Collection<GrantedAuthority> roles = new ArrayList<GrantedAuthority>();
				
				// Add roles that have been assigned in external Drupal instance
				try {
					SortedSet<GeoServerRole> serviceAssignedRoles = userGroupService
							.getRolesForUser(token.getPrincipal().toString());
					roles.addAll(serviceAssignedRoles);
				} catch (IOException e) {
					LOGGER.log(Level.SEVERE, "Failed to get roles for user.", e);
					return null;
				}

				UsernamePasswordAuthenticationToken result = new UsernamePasswordAuthenticationToken(
						token.getPrincipal(), password, roles);
				result.setDetails(token.getDetails());
				LOGGER.info("Instructing GeoServer to accept user: "
						+ token.getPrincipal());
				LOGGER.info("Its roles:");
				for (GrantedAuthority role : roles) {
					LOGGER.info(role.getAuthority());
				}
				return result;
			}
			LOGGER.info("User " + token.getPrincipal() + " failed to authorize");
			return null;
		} catch (SQLException e) {
			LOGGER.log(
					Level.SEVERE,
					"Cannot verify credentials for Drupal user "
							+ token.getPrincipal(), e);
			return null;
		}
	}

	/**
	 * @see http://api.drupal.org/api/drupal/includes!password.inc/function/
	 *      user_check_password/7
	 * @param password
	 * @param accountPass
	 * @return
	 */
	private boolean drupalUserCheckPassword(String password, String accountPass) {
		String storedHash;
		if (password.startsWith("U$")) {
			storedHash = accountPass.substring(1);
			try {
				byte[] md5Binary = MessageDigest.getInstance("MD5").digest(
						password.getBytes("UTF-8"));
				password = String.valueOf(Hex.encodeHex(md5Binary));
			} catch (NoSuchAlgorithmException e) {
				LOGGER.log(Level.SEVERE, e.getMessage(), e);
			} catch (UnsupportedEncodingException e) {
				LOGGER.log(Level.SEVERE, e.getMessage(), e);
			}
		} else {
			storedHash = accountPass;
		}
		assert storedHash != null : "Stored hashes must not be empty";

		if (!storedHash.startsWith("$S$")) {
			LOGGER.severe("Only Drupal 7 hashing variant is supported.");
			return false;
		}

		String hash = drupalPasswordCrypt("SHA-512", password, storedHash);
		LOGGER.finer("Calculated hash is " + hash);
		assert hash != null && hash.length() > 0 : "Only non-empty hashes are valid";

		return storedHash.equals(hash);
	}

	/**
	 * @see http://api.drupal.org/api/drupal/includes!password.inc/function/
	 *      _password_crypt/7
	 * @param algo
	 * @param password
	 * @param setting
	 * @return
	 */
	private String drupalPasswordCrypt(String algo, String password,
			String setting) {
		if (!"SHA-512".equals(algo)) {
			LOGGER.severe("Algorithm not supported");
			return null;
		}

		setting = setting.substring(0, 12);

		int countLog2 = drupalPasswordGetCountLog2(setting);
		String salt = setting.substring(4, 12);
		int count = 1 << countLog2;

		byte[] hash = phpHash(algo,
				concat(salt.getBytes(), password.getBytes()), true);
		do {
			hash = phpHash(algo, concat(hash, password.getBytes()), true);
			count = count - 1;
		} while (count > 0);

		int len = hash.length;
		String output = setting + drupalPasswordBase64Encode(hash, len);
		return output.substring(0, DRUPAL_HASH_LENGTH);
	}

	/**
	 * Concatenates 2 byte arrays
	 * 
	 * @param first
	 * @param second
	 * @return All elements of first followed by all elements of second
	 */
	private byte[] concat(byte[] first, byte[] second) {
		byte[] combination = new byte[first.length + second.length];
		System.arraycopy(first, 0, combination, 0, first.length);
		System.arraycopy(second, 0, combination, first.length, second.length);
		return combination;
	}

	/**
	 * @see http://api.drupal.org/api/drupal/includes!password.inc/function/
	 *      _password_base64_encode/7
	 * @param hash
	 * @param count
	 * @return
	 */
	public String drupalPasswordBase64Encode(final byte[] hash, final int count) {
		final StringBuilder output = new StringBuilder();
		int i = 0;
		final String itoa64 = drupalPasswordItoa64();
		do {
			// Integer need to be used to get common unsigned integer
			// representation for shift and bitwise operators
			int value = toPhpCharCode(hash[i++]);
			output.append(itoa64.charAt(value & 0x3f));
			if (i < count) {
				value |= (toPhpCharCode(hash[i]) << 8);
			}
			output.append(itoa64.charAt((value >> 6) & 0x3f));
			if (i++ >= count) {
				break;
			}
			if (i < count) {
				value |= (toPhpCharCode(hash[i]) << 16);
			}
			output.append(itoa64.charAt((value >> 12) & 0x3f));
			if (i++ >= count) {
				break;
			}
			output.append(itoa64.charAt((value >> 18) & 0x3f));
		} while (i < count);
		return output.toString();
	}

	/**
	 * @param a
	 *            Java byte representation
	 * @return PHP byte representation (character value as in a PHP string)
	 */
	private int toPhpCharCode(byte a) {
		int high = (0xF0 & a) >>> 4;
		int low = 0x0F & a;
		return (high << 4) | low;
	}

	/**
	 * @see http://de.php.net/manual/en/function.hash.php
	 * @param algo
	 * @param bs
	 * @param raw_output
	 * @return
	 */
	private byte[] phpHash(String algo, byte[] bs, boolean raw_output) {
		if (!"SHA-512".equals(algo)) {
			LOGGER.severe("Algorithm not supported");
			return null;
		}
		if (!raw_output) {
			LOGGER.severe("Only raw data is supported by PHP hash reimplementation");
		}
		try {
			return MessageDigest.getInstance("SHA-512").digest(bs);
		} catch (NoSuchAlgorithmException e) {
			LOGGER.log(Level.SEVERE, e.getMessage(), e);
		}
		// Hopefully signalize invalid data
		return new byte[0];
	}

	/**
	 * @see _password_get_count_log2 in includes/password.inc
	 * @param settings
	 * @return
	 */
	private int drupalPasswordGetCountLog2(String settings) {
		String itoa64 = drupalPasswordItoa64();
		return itoa64.indexOf(settings.charAt(3));
	}

	/**
	 * @see http://api.drupal.org/api/drupal/includes!password.inc/function/
	 *      _password_itoa64/7
	 * @return
	 */
	private String drupalPasswordItoa64() {
		return "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
	}
}
