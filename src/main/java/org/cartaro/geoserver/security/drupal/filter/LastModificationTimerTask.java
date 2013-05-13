package org.cartaro.geoserver.security.drupal.filter;

import java.lang.ref.WeakReference;
import java.util.TimerTask;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.geotools.util.logging.Logging;

class LastModificationTimerTask extends TimerTask {

	static final Logger LOGGER = Logging.getLogger("org.geoserver.security");

    private WeakReference<LastModificationTriggerable> lastModificationTriggerable;

    protected LastModificationTimerTask(LastModificationTriggerable triggerable) {
    	LOGGER.log(Level.FINEST, "Creating LastModificationTimerTask");
        this.lastModificationTriggerable = 
                new WeakReference<LastModificationTriggerable>(triggerable);
    }

    @Override
    public void run() {
        LastModificationTriggerable triggerable = this.lastModificationTriggerable.get();
        if (triggerable == null) {
            // triggerable has been garbage collected and does not exist anymore
            LOGGER.log(Level.FINEST, "Cancelling LastModificationTimerTask");
            this.cancel();
        }
        else {
            triggerable.setLastModified(System.currentTimeMillis());
        }
        triggerable = null;
    }
}
