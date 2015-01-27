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

package org.wso2.carbon.identity.certificateauthority.endpoint.util;

import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.identity.certificateauthority.services.CAConfigurationService;
import org.wso2.carbon.identity.certificateauthority.services.CRLService;
import org.wso2.carbon.identity.certificateauthority.services.CertificateService;
import org.wso2.carbon.identity.certificateauthority.services.OCSPService;
import org.wso2.carbon.identity.certificateauthority.services.SCEPService;

/**
 * Contais util methods needed by the CA endpoint classes.
 */
public class CAEndpointUtils {

    private CAEndpointUtils() {
    }

    /**
     * Gets the CA Configuration OSGi Service.
     *
     * @return
     */
    public static CAConfigurationService getCaConfigurationService() {
        return (CAConfigurationService) CarbonContext.getThreadLocalCarbonContext().getOSGiService(
                CAConfigurationService.class, null);
    }

    /**
     * Gets the OSGi Service related to certificate operations.
     * @return
     */
    public static CertificateService getCertificateService() {
        return (CertificateService) CarbonContext.getThreadLocalCarbonContext().getOSGiService(CertificateService
                .class, null);
    }

    /**
     * Gets the OSGi Service related to SCEP operations.
     * @return
     */
    public static SCEPService getSCEPService() {
        return (SCEPService) CarbonContext.getThreadLocalCarbonContext().getOSGiService(SCEPService.class, null);
    }

    /**
     * Gets the OSGi Service related to CRL operations.
     * @return
     */
    public static CRLService getCRLService() {
        return (CRLService) CarbonContext.getThreadLocalCarbonContext().getOSGiService(CRLService.class, null);
    }

    /**
     * Gets the OSGi Service related to OCSP operations.
     * @return
     */
    public static OCSPService getOCSPService() {
        return (OCSPService) CarbonContext.getThreadLocalCarbonContext().getOSGiService(OCSPService.class, null);
    }

}
