Drupal as user provider for GeoServer
=====================================
This GeoServer extension allows to use any number of Drupal instances as user providers.

Installation
============
Copy the jar file of the desired version into ``geoserver/WEB-INF/lib/`` within your servlet container. In case you use Tomcat to run GeoServer the path will be similar to ``/var/lib/tomcat7/webapps/geoserver/WEB-INF/lib/``.

GeoServer version 2.2 and Drupal 7 running on Postgres are required.

Configuration
=============
You need to configure an *Authentication Provider* which is responsible for logging in users. Additionally you will also need to set up a *User Group Service* and a *Role Service*. Even though GeoServer does not couple these services you should bind all of these service types to Drupal in order to get users and roles from your Drupal instance.

Log into GeoServer using your ``root`` user or another user with administrative privileges.

Click *Authentication* in the left sidebar, then add a new *Authentication Provider*. Make sure to select type *Drupal* and fill in your details in the form that appears. Note that the service's name will be used as a prefix for users derived from Drupal. The provider needs to be selected for the provider chain in order to be used.

Now open *Users, Groups and Roles* from the left sidebar. Add a new *User Group Service* of type *Drupal* and enter the same data as before. Select *plain text* as password encryption since Drupal hashes passwords itself. Make sure to use the same service name as for the *Authentication Provider*.

Finally add a new *Role Service* of type *Drupal*. Choose whatever name you desire but ensure to set it as active role servie in ``geoserver/data/security/config.xml``.

Workings
========
GeoServer allows any number of active services for authentication and user/group listing at the same time. It does however only support one active role service at a time. Thus the role service for Drupal queries all user group services that belong to Drupal in row and aggregates their roles.

This leads to having exactly one role service in total and one authentication provider and one user-group service per Drupal instance.

Roles and users from Drupal are currently read-only in GeoServer. Use the Drupal's GUI to create users, roles or to assign roles to users.

Permission Mapping
------------------
<table>
	<tr><th>Drupal Permission, group GeoServer</th><th>GeoServer Permission</th></tr>
	<tr><td>*Administer GeoServer*</td><td>Admin</td></tr>
	<tr><td>*Edit any content*</td><td>Write</td></tr>
	<tr><td>*View any content*</td><td>View</td>
</table>
All administrative permissions set by Drupal do only affect the workspace that is named as the Drupal binding in GeoServer. REST services are filtered based on the layer permissions.

Note that Drupal requires *View published content* to be set even if a user is only about to view or create its own content. Edge-cases of the Drupal permission system that are not stored in the database are not necessarily honored by GeoServer – use permissions bound via roles instead.

License
=======
Copyright (C) 2012  geOps e. K.<br>
https://www.geops.de/

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License along
with this program; if not, write to the Free Software Foundation, Inc.,
51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.