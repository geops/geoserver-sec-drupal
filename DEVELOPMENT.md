Notes to document the development process
=========================================

Creating a new release
----------------------

Steps to create a new release:

* Set the version number in pom.xml (Node /project/version)
* Run `mvn install` to build the new release JAR
* Commit the changed pom.xml
* Create a tag for this version number in git
* Push the commit and the tag to github.
* Provide a download for the JAR file
