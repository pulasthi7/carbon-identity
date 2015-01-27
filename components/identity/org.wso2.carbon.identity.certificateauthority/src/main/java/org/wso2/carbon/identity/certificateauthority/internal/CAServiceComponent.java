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

package org.wso2.carbon.identity.certificateauthority.internal;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.osgi.framework.BundleContext;
import org.osgi.service.component.ComponentContext;
import org.wso2.carbon.identity.certificateauthority.CAConstants;
import org.wso2.carbon.identity.certificateauthority.config.CAConfiguration;
import org.wso2.carbon.identity.certificateauthority.scheduledTask.CRLUpdater;
import org.wso2.carbon.identity.certificateauthority.services.CAConfigurationService;
import org.wso2.carbon.identity.certificateauthority.services.CAConfigurationServiceImpl;
import org.wso2.carbon.identity.certificateauthority.services.CRLService;
import org.wso2.carbon.identity.certificateauthority.services.CRLServiceImpl;
import org.wso2.carbon.identity.certificateauthority.services.CSRService;
import org.wso2.carbon.identity.certificateauthority.services.CSRServiceImpl;
import org.wso2.carbon.identity.certificateauthority.services.CertificateService;
import org.wso2.carbon.identity.certificateauthority.services.CertificateServiceImpl;
import org.wso2.carbon.identity.certificateauthority.services.OCSPService;
import org.wso2.carbon.identity.certificateauthority.services.OCSPServiceImpl;
import org.wso2.carbon.identity.certificateauthority.services.SCEPService;
import org.wso2.carbon.identity.certificateauthority.services.SCEPServiceImpl;
import org.wso2.carbon.user.core.service.RealmService;

import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * @scr.component name="identity.certificateauthority" immediate="true"
 * @scr.reference name="user.realmservice.default" interface="org.wso2.carbon.user.core.service.RealmService"
 * cardinality="1..1" policy="dynamic" bind="setRealmService"
 * unbind="unsetRealmService"
 */
public class CAServiceComponent {

    private static RealmService realmService;
    private static Log log = LogFactory.getLog(CAServiceComponent.class);
    private static CSRService csrService;
    private static CertificateService certificateService;
    private static CRLService crlService;
    private static OCSPService ocspService;
    private static SCEPService scepService;
    private static CAConfigurationService caConfigurationService;
    private final ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);

    public static RealmService getRealmService() {
        return realmService;
    }

    protected void setRealmService(RealmService realmService) {
        CAServiceComponent.realmService = realmService;
    }

    public static CSRService getCsrService() {
        return csrService;
    }

    public static CertificateService getCertificateService() {
        return certificateService;
    }

    public static CRLService getCrlService() {
        return crlService;
    }

    public static OCSPService getOcspService() {
        return ocspService;
    }

    public static SCEPService getScepService() {
        return scepService;
    }

    public static CAConfigurationService getCaConfigurationService() {
        return caConfigurationService;
    }

    protected void unsetRealmService(RealmService realmService) {
        setRealmService(null);
    }

    protected void activate(ComponentContext ctxt) {
        BundleContext bundleContext = ctxt.getBundleContext();

        //initialize configurations from file
        CAConfiguration caConfiguration = CAConfiguration.getInstance();
        caConfiguration.initialize();

        //initialize services
        caConfigurationService = CAConfigurationServiceImpl.getInstance();
        csrService = CSRServiceImpl.getInstance();
        certificateService = CertificateServiceImpl.getInstance();
        crlService = CRLServiceImpl.getInstance();
        ocspService = OCSPServiceImpl.getInstance();
        scepService = SCEPServiceImpl.getInstance();

        //register OSGI services
        bundleContext.registerService(CSRService.class, csrService, null);
        bundleContext.registerService(CertificateService.class, certificateService, null);
        bundleContext.registerService(CRLService.class, crlService, null);
        bundleContext.registerService(OCSPService.class, ocspService, null);
        bundleContext.registerService(SCEPService.class, scepService, null);

        //Schedule the CRL creation and update
        scheduler.scheduleAtFixedRate(new CRLUpdater(), CAConstants.CRL_UPDATER_INITIAL_DELAY,
                CAConstants.CRL_UPDATE_INTERVAL, TimeUnit.SECONDS);
        log.info("Activated scheduled task for creating and updating CRLs");
    }

    protected void deactivate(ComponentContext ctxt) {
        if (log.isDebugEnabled()) {
            log.debug("CA component is deactivating ...");
        }
    }
}
