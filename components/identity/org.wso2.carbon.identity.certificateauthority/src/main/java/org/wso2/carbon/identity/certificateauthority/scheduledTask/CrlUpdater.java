/*
 * Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
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
import org.wso2.carbon.identity.certificateauthority.CaException;
import org.wso2.carbon.identity.certificateauthority.CrlManager;
import org.wso2.carbon.identity.certificateauthority.internal.CaServiceComponent;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserRealmService;
import org.wso2.carbon.user.api.UserStoreException;

/**
 * Schedules the updating of CRLs
 */
public class CrlUpdater implements Runnable {
    private static final Log log = LogFactory.getLog(CrlUpdater.class);

    /**
     * Builds the full CRLs for each tenant CA
     * @throws CaException
     */
    public void buildFullCrl() throws CaException {
        UserRealmService service = CaServiceComponent.getRealmService();
        PrivilegedCarbonContext.startTenantFlow();
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(MultitenantConstants
                .SUPER_TENANT_ID);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain
                (MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        CrlManager.getInstance().createAndStoreCrl(MultitenantConstants.SUPER_TENANT_ID);
        PrivilegedCarbonContext.endTenantFlow();

        try {
            for (Tenant tenant : service.getTenantManager().getAllTenants()) {
                PrivilegedCarbonContext.startTenantFlow();
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenant.getId());
                PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain
                        (tenant.getDomain());
                CrlManager.getInstance().createAndStoreCrl(tenant.getId());
                PrivilegedCarbonContext.endTenantFlow();
            }
        } catch (UserStoreException e) {
            log.error("Error getting tenant list", e);
            throw new CaException("CRL list was not build, Error when accessing tenants", e);
        }
    }

    @Override
    public void run() {
        try {
            if(log.isDebugEnabled()){
                log.debug("Creating full CRLs for tenants...");
            }
            buildFullCrl();
        } catch (Exception e) {
            log.error("Error when updating CRL", e);
        }
    }
}


