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

	private Timer timer;

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
			timer = new Timer();
			timer.scheduleAtFixedRate(new TimerTask() {
				@Override
				public void run() {
					try {
						DrupalDatabaseConnector.this.connection = DrupalDatabaseConnector.this.accquireConnection(drupalConfig);
						timer.cancel();
						timer = null;
						LOGGER.log(Level.INFO, "Finally connected to database of configuration "+drupalConfig.getName());
					} catch (SQLException e) {
						LOGGER.log(Level.WARNING, "Cannot connect to database of configuration "+drupalConfig.getName(), e);
					}
				}
			}, 5000, 5000);
		}
	}
	
	/**
	 * Closes database connection if any is still open.
	 * Subsequent simply won't have any effect.
	 */
	public void close(){
		if(timer!=null){
			timer.cancel();
			timer = null;
			LOGGER.log(Level.WARNING, "Don't try failing connection attempts to database of configuration "+instancePrefix+" any longer.");
		}
		if(this.connection!=null){
			try {
				this.connection.close();
			} catch (SQLException e) {
				LOGGER.log(Level.WARNING, "Could not close database connection of "+instancePrefix, e);
			}
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
		if(!hasInstancePrefix(prefixed)){
			throw new IllegalArgumentException("Does not have prefix to be stripped: "+prefixed);
		}
		return prefixed.substring(instancePrefix.length());
	}
	
	/**
	 * @param prefixed Text to check for sharing prefix with this instance's connection
	 * @return True if prefixes are shared
	 */
	public boolean hasInstancePrefix(String prefixed){
		return prefixed.startsWith(instancePrefix);
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
		// Convert using convert_from to get consistent behavior in Postgres 8 and 9
		ResultSet drupalCurrentlyInstallingSet = this.getResultSet("select convert_from(value, 'UTF-8')='s:23:\"install_profile_modules\";' as install_profile_modules " +
				"from variable where name='install_task'");
		boolean drupalCurrentlyInstalling = drupalCurrentlyInstallingSet.next() && drupalCurrentlyInstallingSet.getBoolean("install_profile_modules");
		return drupalCurrentlyInstalling;
	}
}
