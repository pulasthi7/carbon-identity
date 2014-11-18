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
import org.wso2.carbon.identity.certificateauthority.crl.CrlFactory;
import org.wso2.carbon.identity.certificateauthority.internal.CaServiceComponent;
import org.wso2.carbon.user.api.Tenant;
import org.wso2.carbon.user.api.UserRealmService;
import org.wso2.carbon.user.api.UserStoreException;

public class CrlUpdater implements Runnable {
    private static final Log log = LogFactory.getLog(CrlUpdater.class);

    public void buildFullCrl() throws CaException {
        CrlFactory crlFactory = new CrlFactory();
        UserRealmService service = CaServiceComponent.getRealmService();
        setTenant(MultitenantConstants.SUPER_TENANT_ID,
                MultitenantConstants.SUPER_TENANT_DOMAIN_NAME);
        crlFactory.createAndStoreCrl(MultitenantConstants.SUPER_TENANT_ID);

        try {
            for (Tenant tenant : service.getTenantManager().getAllTenants()) {
                setTenant(tenant.getId(), tenant.getDomain());
                crlFactory.createAndStoreCrl(tenant.getId());
            }
        } catch (UserStoreException e) {
            log.error("Error getting tenant list", e);
            throw new CaException("CRL list was not build, Error when accessing tenants", e);
        }
    }

    @Override
    public void run() {
        try {
            log.debug("Creating full CRLs for tenants...");
            buildFullCrl();
        } catch (Exception e) {
            log.error("Error when updating CRL", e);
        }
    }

    public void setTenant(int tenantId, String tenantDomain) {
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantId(tenantId);
        PrivilegedCarbonContext.getThreadLocalCarbonContext().setTenantDomain(tenantDomain);
    }
}


