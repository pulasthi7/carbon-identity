package org.wso2.carbon.identity.analytic.core.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.analytic.core.Configuration;

/**
 * @scr.component name="org.wso2.carbon.identity.analytic.core" immediate="true"
 */
public class AnalyticCoreServiceComponent {

    private static Log log = LogFactory.getLog(AnalyticCoreServiceComponent.class);

    protected void activate(ComponentContext context) {

        try {
            Configuration.init();
        } catch (Throwable e) {
            log.error("Error occurred while activating WorkflowImplServiceComponent bundle, ", e);
        }

    }

}
