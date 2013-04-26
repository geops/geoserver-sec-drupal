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
	private final String instancePrefix;

	private Timer timer;

	private final DrupalSecurityServiceConfig drupalConfig;

	/**
	 * Binds an instance to a Drupal database and repeatedly retries if
	 * connection fails.
	 * 
	 * @param drupalConfig
	 * @throws ClassNotFoundException
	 */
	public DrupalDatabaseConnector(
			final DrupalSecurityServiceConfig drupalConfig)
			throws ClassNotFoundException {
		this.drupalConfig = drupalConfig;
		instancePrefix = drupalConfig.getDrupalInstancePrefix();

		Class.forName("org.postgresql.Driver");
	}

	/**
	 * Closes database connection if any is still open. Subsequent simply won't
	 * have any effect.
	 */
	public void close() {
		if (timer != null) {
			timer.cancel();
			timer = null;
			LOGGER.log(Level.WARNING,
					"Don't try failing connection attempts to database of configuration "
							+ instancePrefix + " any longer.");
		}
		if (this.connection != null) {
			try {
				this.connection.close();
				this.connection = null;
			} catch (SQLException e) {
				LOGGER.log(Level.WARNING,
						"Could not close database connection of "
								+ instancePrefix, e);
			}
		}
	}

	/**
	 * Tries to get a new database connection.
	 * 
	 * @param drupalConfig
	 * @return New database connection.
	 * @throws SQLException
	 */
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

	/**
	 * @param query
	 *            SQL query to run.
	 * @return Query result
	 * @throws SQLException
	 */
	public ResultSet getResultSet(final String query) throws SQLException {
		return new SqlTask() {
			@Override
			protected ResultSet perform(Connection connection)
					throws SQLException {
				Statement statement = connection.createStatement();
				return statement.executeQuery(query);
			}
		}.run();
	}

	public GeoServerRole stripInstancePrefix(GeoServerRole role) {
		String prefixedRole = role.getAuthority();
		String unprefixed = stripInstancePrefix(prefixedRole);
		return new GeoServerRole(unprefixed);
	}

	/**
	 * @param query
	 *            SQL query to run.
	 * @param parameter
	 *            Value for the placeholder.
	 * @return Query result.
	 * @throws SQLException
	 */
	public ResultSet getResultSet(final String query, final String parameter)
			throws SQLException {
		return new SqlTask() {
			@Override
			protected ResultSet perform(Connection connection)
					throws SQLException {
				PreparedStatement ps = connection.prepareStatement(query);
				ps.setString(1, parameter);
				return ps.executeQuery();
			}
		}.run();
	}

	public GeoServerRole addInstancePrefix(GeoServerRole role) {
		return new GeoServerRole(addInstancePrefix(role.getAuthority()));
	}

	/**
	 * @param prefixed
	 * @return
	 * @throws IllegalArgumentException
	 *             When prefix can't be stripped because it is not there
	 */
	public String stripInstancePrefix(String prefixed) {
		if (!hasInstancePrefix(prefixed)) {
			throw new IllegalArgumentException(
					"Does not have prefix to be stripped: " + prefixed);
		}
		return prefixed.substring(instancePrefix.length());
	}

	/**
	 * @param prefixed
	 *            Text to check for sharing prefix with this instance's
	 *            connection
	 * @return True if prefixes are shared
	 */
	public boolean hasInstancePrefix(String prefixed) {
		return prefixed.startsWith(instancePrefix);
	}

	/**
	 * Prepend a value with and instance prefix
	 * 
	 * @param string
	 * @return
	 */
	public String addInstancePrefix(String string) {
		return instancePrefix + string;
	}

	/**
	 * @return TRUE whilst the bound Drupal instance is still installing its
	 *         core (initial installation)
	 * @throws SQLException
	 */
	public boolean isDrupalCurrentlyInstalling() throws SQLException {
		// Convert using convert_from to get consistent behavior in Postgres 8
		// and 9.
		ResultSet drupalCurrentlyInstallingSet = this
				.getResultSet("select convert_from(value, 'UTF-8')='s:23:\"install_profile_modules\";' as install_profile_modules "
						+ "from variable where name='install_task'");
		boolean drupalCurrentlyInstalling = drupalCurrentlyInstallingSet.next()
				&& drupalCurrentlyInstallingSet
						.getBoolean("install_profile_modules");
		return drupalCurrentlyInstalling;
	}

	/**
	 * Acts on the database connection and repeat actions if failed due to
	 * missing database. Can only be run once.
	 */
	abstract class SqlTask {
		/**
		 * Maximum number of times {@link #perform(Connection)} is tried before
		 * giving up.
		 */
		protected int maxRetries = 3;

		/**
		 * Milliseconds to wait before trying {@link #perform(Connection)}
		 * again.
		 */
		protected int retryInterval = 10000;

		/**
		 * Query result determined during retries.
		 */
		private ResultSet result;

		private boolean used = false;

		/**
		 * Job that is to be done using the given connection. Called multiple
		 * times in case of connection failures.
		 * 
		 * @param connection
		 * @return Result to return when {@link #run()} gets called.
		 * @throws SQLException
		 */
		protected abstract ResultSet perform(Connection connection)
				throws SQLException;

		/**
		 * @param e
		 * @return True if exception denotes a connection failure / allows for
		 *         retrying.
		 */
		boolean isRetyable(SQLException e) {
			// See codes in
			// http://www.postgresql.org/docs/current/static/errcodes-appendix.html
			String[] retryables = { "08", "57" };
			for (String sqlStateStart : retryables) {
				if (e.getSQLState().startsWith(sqlStateStart)) {
					return true;
				}
			}
			return false;
		}

		/**
		 * Ensure a database connection is available and calls
		 * {@link #perform(Connection)}.
		 * 
		 * @return Whatever {@link #perform(Connection)} returns.
		 * @throws SQLException
		 */
		private ResultSet accquireAndPerform() throws SQLException {
			if (connection == null) {
				connection = DrupalDatabaseConnector.this
						.accquireConnection(drupalConfig);
			}
			return this.perform(connection);
		}

		/**
		 * Calls perform repeatedly until it succeeds or {@link #maxRetries}
		 * reached.
		 * 
		 * @return Result of {@link #perform(Connection)}.
		 * @throws SQLException
		 */
		public ResultSet run() throws SQLException {
			if (used) {
				throw new IllegalStateException(
						"Task has already been run. Aborted run as internal state might be tainted.");
			}
			used = true;

			try {
				// Try execution without delays.
				return accquireAndPerform();
			} catch (SQLException e) {
				if (isRetyable(e)) {
					// Discards invalid database connection.
					DrupalDatabaseConnector.this.close();

					final Timer timer = new Timer();
					timer.scheduleAtFixedRate(new TimerTask() {

						/**
						 * Retries calling {@link #perform(Connection)}.
						 */
						@Override
						public void run() {
							maxRetries = maxRetries - 1;
							synchronized (SqlTask.this) {
								if (maxRetries > 0) {
									try {
										result = accquireAndPerform();
										abortRetrying(timer);
									} catch (SQLException e) {
										if (isRetyable(e)) {
											DrupalDatabaseConnector.this
													.close();

											// Await next interval.
											LOGGER.log(
													Level.INFO,
													"Failed query, will repeat.",
													e);
										} else {
											abortRetrying(timer);
										}
									}
								} else {
									abortRetrying(timer);
								}
							}
						}

						/**
						 * Cancels retrying and propagates result.
						 * 
						 * @param timer
						 */
						private void abortRetrying(final Timer timer) {
							timer.cancel();
							SqlTask.this.notify();
						}

					}, retryInterval, retryInterval);

					// Await availability of result.
					try {
						synchronized (this) {
							// Keep waiting until query result is known.
							while (maxRetries > 0 && result == null) {
								this.wait();
							}
						}
						LOGGER.info("done waiting");
					} catch (InterruptedException e1) {
						LOGGER.info("interrupt in db recovery");
					}
					if (result == null) {
						// Report original failure.
						LOGGER.severe("got result after recovery");
						throw e;
					} else {
						// Report result determined by retries.
						LOGGER.info("got result after recovery");
						return result;
					}
				}
				throw e;
			}
		}
	}
}
