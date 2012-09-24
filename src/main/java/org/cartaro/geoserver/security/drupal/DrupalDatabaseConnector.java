package org.cartaro.geoserver.security.drupal;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Timer;
import java.util.TimerTask;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.geoserver.security.impl.GeoServerRole;
import org.geotools.util.logging.Logging;

/**
 * Abstracts access to a Drupal database
 */
public class DrupalDatabaseConnector {
	static final Logger LOGGER = Logging.getLogger("org.geoserver.security");
	
	private Connection connection;
	
	/**
	 * Value prepended to Drupal users and roles
	 */
	private String instancePrefix;

	/**
	 * Binds an instance to a Drupal database and repeatedly retries if connection fails.
	 * @param drupalConfig
	 * @throws ClassNotFoundException
	 */
	public DrupalDatabaseConnector(final DrupalSecurityServiceConfig drupalConfig)
			throws ClassNotFoundException {
		instancePrefix = drupalConfig.getDrupalInstancePrefix();
		
		Class.forName("org.postgresql.Driver");
		try{
			this.connection = this.accquireConnection(drupalConfig);
		} catch (SQLException e){
			// Try reconnecting of connection failed
			LOGGER.log(Level.WARNING, "Cannot connect to database of configuration "+drupalConfig.getName()+". Retrying in 5000ms interval.", e);
			final Timer timer = new Timer();
			timer.scheduleAtFixedRate(new TimerTask() {
				@Override
				public void run() {
					try {
						DrupalDatabaseConnector.this.connection = DrupalDatabaseConnector.this.accquireConnection(drupalConfig);
						timer.cancel();
					} catch (SQLException e) {
						LOGGER.log(Level.WARNING, "Cannot connect to database of configuration "+drupalConfig.getName(), e);
					}
				}
			}, 5000, 5000);
		}
	}

	protected Connection accquireConnection(
			DrupalSecurityServiceConfig drupalConfig) throws SQLException {
		String connectionURL = "jdbc:postgresql://"
				+ drupalConfig.getDatabaseHost() + ":"
				+ drupalConfig.getDatabasePort() + "/"
				+ drupalConfig.getDatabaseName() + "?user="
				+ drupalConfig.getDatabaseUser() + "&password="
				+ drupalConfig.getDatabasePassword();
		return DriverManager.getConnection(connectionURL);
	}

	public ResultSet getResultSet(String query) throws SQLException {
		Statement statement = this.connection.createStatement();
		return statement.executeQuery(query);
	}

	public GeoServerRole stripInstancePrefix(GeoServerRole role) {
		String prefixedRole = role.getAuthority();
		String unprefixed = stripInstancePrefix(prefixedRole);
		return new GeoServerRole(unprefixed);
	}

	public ResultSet getResultSet(String query, String parameter)
			throws SQLException {
		PreparedStatement ps = this.connection.prepareStatement(query);
		ps.setString(1, parameter);
		return ps.executeQuery();
	}

	public GeoServerRole addInstancePrefix(GeoServerRole role) {
		return new GeoServerRole(addInstancePrefix(role.getAuthority()));
	}

	/**
	 * @param prefixed
	 * @return
	 * @throws IllegalArgumentException When prefix can't be stripped because it is not there
	 */
	public String stripInstancePrefix(String prefixed) {
		if(!prefixed.startsWith(instancePrefix)){
			throw new IllegalArgumentException("Does not have prefix to be stripped: "+prefixed);
		}
		return prefixed.substring(instancePrefix.length());
	}

	/**
	 * Prepend a value with and instance prefix
	 * @param string
	 * @return
	 */
	public String addInstancePrefix(String string) {
		return instancePrefix + string;
	}
	
	/**
	 * @return TRUE whilst the bound Drupal instance is still installing its core (initial installation)
	 * @throws SQLException
	 */
	public boolean isDrupalCurrentlyInstalling() throws SQLException{
		ResultSet drupalCurrentlyInstallingSet = this.getResultSet("select value::text='s:23:\"install_profile_modules\";' as install_profile_modules " +
				"from variable where name='install_task'");
		boolean drupalCurrentlyInstalling = drupalCurrentlyInstallingSet.next() && drupalCurrentlyInstallingSet.getBoolean("install_profile_modules");
		return drupalCurrentlyInstalling;
	}
}
