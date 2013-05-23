package org.cartaro.geoserver.security.drupal.filter;

abstract interface LastModificationTriggerable {

    /**
     * set the new lastModifed timestamp
     */
    abstract void setLastModified(long newLastModified);

}
