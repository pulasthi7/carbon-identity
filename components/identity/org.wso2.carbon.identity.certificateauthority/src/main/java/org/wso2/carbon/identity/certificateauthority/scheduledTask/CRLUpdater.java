/*
 * Copyright (c) 2015 WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.certificateauthority.scheduledTask;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.certificateauthority.CAException;
import org.wso2.carbon.identity.certificateauthority.CRLManager;
import org.wso2.carbon.identity.certificateauthority.internal.CAServiceComponent;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserRealmService;
import org.wso2.carbon.user.api.UserStoreException;

/**
 * Schedules the updating of CRLs
 */
public class CRLUpdater implements Runnable {
    private static final Log log = LogFactory.getLog(CRLUpdater.class);

    /**
     * Builds the full CRLs for each tenant CA
     *
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public void buildFullCrl() throws CAException {
        UserRealmService service = CAServiceComponent.getRealmService();
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(MultitenantConstants
                .SUPER_TENANT_ID);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain
                (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        CRLManager crlManager = new CRLManager();
        crlManager.createAndStoreCrl(MultitenantConstants.SUPER_TENANT_ID);
        PrivilegedCarbonContext.endTenantFlow();

        try {
            for (Tenant tenant : service.getTenantManager().getAllTenants()) {
                PrivilegedCarbonContext.startTenantFlow();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenant.getId());
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain
                        (tenant.getDomain());
                crlManager.createAndStoreCrl(tenant.getId());
                PrivilegedCarbonContext.endTenantFlow();
            }
        } catch (UserStoreException e) {
            log.error("Error getting tenant list", e);
            throw new CAException("CRL list was not build, Error when accessing tenants", e);
        }
    }

    @Override
    public void run() {
        try {
            if (log.isDebugEnabled()) {
                log.debug("Creating full CRLs for tenants...");
            }
            buildFullCrl();
        } catch (Exception e) {
            log.error("Error when updating CRL", e);
        }
    }
}


