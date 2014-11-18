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

package org.wso2.carbon.identity.certificateauthority;

import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.identity.certificateauthority.crl.CrlFactory;
import org.wso2.carbon.identity.certificateauthority.dao.CrlDAO;
import org.wso2.carbon.identity.certificateauthority.internal.CaServiceComponent;
import org.wso2.carbon.identity.certificateauthority.scheduledTask.CrlUpdater;
import org.wso2.carbon.identity.certificateauthority.utils.ConversionUtils;
import org.wso2.carbon.user.api.UserStoreException;

import java.io.UnsupportedEncodingException;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.X509CRL;

public class CrlManager {
    private CrlDAO crlDAO = new CrlDAO();

    public void addCRL() throws Exception {
        CrlFactory factory = new CrlFactory();
        int tenantID = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        factory.createAndStoreCrl(tenantID);
    }

    public void addDeltaCrl() throws Exception {
        CrlFactory factory = new CrlFactory();
        int tenantID = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        factory.createAndStoreDeltaCrl(tenantID);
    }

    public byte[] getLatestCrl(String tenantDomain)
            throws CaException {
        try {
            int tenantId = CaServiceComponent.getRealmService().getTenantManager().getTenantId
                    (tenantDomain);
            return crlDAO.getLatestCRL(tenantId, false).getBase64Crl().getBytes(
                    CaConstants.UTF_8_CHARSET);
        } catch (UnsupportedEncodingException e) {
            throw new CaException("Unsupported encoding used", e);
        } catch (UserStoreException e) {
            throw new CaException("Invalid tenant domain", e);
        }
    }

    public byte[] getLatestDeltaCrl(String tenantDomain)
            throws CaException {
        try {
            int tenantId = CaServiceComponent.getRealmService().getTenantManager().getTenantId
                    (tenantDomain);
            return crlDAO.getLatestCRL(tenantId, true).getBase64Crl()
                    .getBytes(CaConstants.UTF_8_CHARSET);
        } catch (UnsupportedEncodingException e) {
            throw new CaException("Unsupported encoding used", e);
        } catch (UserStoreException e) {
            throw new CaException("Invalid tenant domain", e);
        }
    }

    public void updateCrl() throws Exception {
        CrlUpdater updater = new CrlUpdater();
        updater.buildFullCrl();
    }

    public X509CRL getLatestX509Crl(int tenantId) throws CaException {
        return ConversionUtils.toX509Crl(crlDAO.getLatestCRL(tenantId, false).getBase64Crl());
    }

    public X509CRL getLatestX509Crl(String tenantDomain) throws CaException {
        int tenantId = 0;
        try {
            tenantId = CaServiceComponent.getRealmService().getTenantManager().getTenantId
                    (tenantDomain);
            return getLatestX509Crl(tenantId);
        } catch (UserStoreException e) {
            throw new CaException("Invalid tenant domain", e);
        }
    }
}
