/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.analytic.core.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.analytic.core.Configuration;
import org.wso2.carbon.identity.analytic.core.EventPublisherService;
import org.wso2.carbon.identity.analytic.core.impl.EventPublisherServiceImpl;
import org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent;


/**
 * @scr.component name="org.wso2.carbon.identity.analytic.core" immediate="true"
 * @scr.reference name="identityCoreInitializedEventService"
 * interface="org.wso2.carbon.identity.core.util.IdentityCoreInitializedEvent" cardinality="1..1"
 * policy="dynamic" bind="setIdentityCoreInitializedEventService" unbind="unsetIdentityCoreInitializedEventService"
 */
public class AnalyticCoreServiceComponent {

    private static Log log = LogFactory.getLog(AnalyticCoreServiceComponent.class);

    protected void activate(ComponentContext context) {

        try {
            Configuration.init();
            EventPublisherServiceImpl eventPublisherServiceImpl = new EventPublisherServiceImpl();
            PublisherServiceValueHolder.setEventPublisherServiceImpl(eventPublisherServiceImpl);
            context.getBundleContext()
                    .registerService(EventPublisherService.class.getName(), eventPublisherServiceImpl, null);
        } catch (Throwable e) {
            log.error("Error occurred while activating AnalyticCoreServiceComponent bundle, ", e);
        }
    }


    protected void unsetIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

    protected void setIdentityCoreInitializedEventService(IdentityCoreInitializedEvent identityCoreInitializedEvent) {
        /* reference IdentityCoreInitializedEvent service to guarantee that this component will wait until identity core
         is started */
    }

}
