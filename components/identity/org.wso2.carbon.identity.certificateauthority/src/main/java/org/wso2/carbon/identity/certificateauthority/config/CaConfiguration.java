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

package org.wso2.carbon.identity.certificateauthority.config;

import org.apache.axiom.om.OMElement;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.context.PrivilegedCarbonContext;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.identity.certificateauthority.CaConstants;
import org.wso2.carbon.identity.certificateauthority.CaException;
import org.wso2.carbon.identity.certificateauthority.CertificateManager;
import org.wso2.carbon.identity.certificateauthority.common.RevokeReason;
import org.wso2.carbon.identity.certificateauthority.dao.ConfigurationDAO;
import org.wso2.carbon.identity.certificateauthority.data.CaConfig;
import org.wso2.carbon.identity.certificateauthority.data.CertificateInfo;
import org.wso2.carbon.identity.certificateauthority.internal.CaServiceComponent;
import org.wso2.carbon.identity.certificateauthority.utils.ConversionUtils;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;
import org.wso2.carbon.registry.core.Registry;
import org.wso2.carbon.security.keystore.KeyStoreAdmin;
import org.wso2.carbon.security.keystore.service.KeyStoreData;
import org.wso2.carbon.user.api.UserStoreException;

import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class CaConfiguration {

    private static CaConfiguration instance = new CaConfiguration();

    private static final Log log = LogFactory.getLog(CaConfiguration.class);

    public static CaConfiguration getInstance() {
        return instance;
    }

    private CaConfiguration() {
        //buildCaConfiguration();
    }

    private void buildCaConfiguration(){
        IdentityConfigParser configParser = null;
        try {
            configParser = IdentityConfigParser.getInstance();
            OMElement caRootElem = configParser.getConfigElement(CaConstants.CA_ROOT_ELEMENT);
            if(caRootElem == null){
                log.error("Certificate Authority configuration was not found in identity.xml");
                return;
            }
            //todo:read configs

        } catch (ServerConfigurationException e) {
           log.error("Error loading CA related configurations.",e);
        } catch (ClassCastException e){
            log.error("SCEP configuration provider should implement ScepConfigProvider " +
                    "interface",e);
        }
    }

    public X509Certificate getConfiguredCaCert() throws CaException {
        int tenantId = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        return getConfiguredCaCert(tenantId);
    }

    public X509Certificate getConfiguredCaCert(int tenantId) throws CaException {
        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
        String tenantDomain =
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();
        ConfigurationDAO configurationDAO = new ConfigurationDAO();
        String keyPath = configurationDAO.getConfiguredKey(tenantId);
        try {
            if (keyPath == null) {
                //Using the default key
                if (tenantId == MultitenantConstants.SUPER_TENANT_ID) {
                    return keyStoreManager.getDefaultPrimaryCertificate();
                } else {
                    String ksName = tenantDomain.trim().replace(".", "-");
                    String jksName = ksName + ".jks";
                    return (X509Certificate) keyStoreManager.getKeyStore(jksName)
                            .getCertificate(tenantDomain);
                }
            }
            String[] storeAndAlias = keyPath.split("/");
            return (X509Certificate) keyStoreManager.getKeyStore(storeAndAlias[0]).getCertificate
                    (storeAndAlias[1]);
        } catch (Exception e) {
            throw new CaException("Error retrieving CA Certificate", e);
        }
    }

    public String getPemEncodedCaCert(String tenantDomain) throws CaException{
        try {
            int tenantId = CaServiceComponent.getRealmService().getTenantManager().getTenantId
                    (tenantDomain);
            return ConversionUtils.toPemEncodedCertificate(getConfiguredCaCert(tenantId));
        } catch (UserStoreException e) {
            throw new CaException("Invalid tenant domain",e);
        }
    }

    public PrivateKey getConfiguredPrivateKey() throws CaException {
        int tenantID = PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantId();
        return getConfiguredPrivateKey(tenantID);
    }

    public PrivateKey getConfiguredPrivateKey(int tenantId) throws CaException {
        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
        String tenantDomain =
                PrivilegedCarbonContext.getThreadLocalCarbonContext().getTenantDomain();

        ConfigurationDAO configurationDAO = new ConfigurationDAO();
        String keyPath = configurationDAO.getConfiguredKey(tenantId);

        try {
            if (keyPath == null) {
                if (tenantId == MultitenantConstants.SUPER_TENANT_ID) {
                    return keyStoreManager.getDefaultPrivateKey();
                } else {
                    String ksName = tenantDomain.trim().replace(".", "-");
                    String jksName = ksName + ".jks";
                    return (PrivateKey) keyStoreManager.getPrivateKey(jksName, tenantDomain);
                }
            }
            String[] storeAndAlias = keyPath.split("/");
            Key privateKey = keyStoreManager.getPrivateKey(storeAndAlias[0],storeAndAlias[1]);
            return (PrivateKey) privateKey;
        } catch (Exception e) {
            throw new CaException("Error retrieving CA's private key", e);
        }
    }

    public List<String> listAllKeys(Registry registry) throws CaException {
        List<String> keyList = new ArrayList<String>();


        try {
            int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
            ConfigurationDAO configurationDAO = new ConfigurationDAO();
            String keyPath = configurationDAO.getConfiguredKey(tenantId);

            if (keyPath != null) {
                //The current configuration will be the first of the list
                keyList.add(keyPath);
            }

            KeyStoreAdmin admin = new KeyStoreAdmin(tenantId, registry);
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
            KeyStoreData[] keyStores =
                    admin.getKeyStores(tenantId == MultitenantConstants.SUPER_TENANT_ID);
            for (KeyStoreData keyStore : keyStores) {
                String keyStoreName = keyStore.getKeyStoreName();
                KeyStore keyStoreManagerKeyStore = keyStoreManager.getKeyStore(keyStoreName);
                Enumeration<String> aliases = keyStoreManagerKeyStore.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    if (keyStoreManagerKeyStore.isKeyEntry(alias)) {
                        keyList.add(keyStoreName + "/" + alias);
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error listing the keys",e);
            throw new CaException("Error listing the keys",e);
        }
        return keyList;
    }


    public void updateKey(int tenantId, String keyStore, String alias) throws CaException {
        ConfigurationDAO configurationDAO = new ConfigurationDAO();
        String currentKeyPath = configurationDAO.getConfiguredKey(tenantId);
        String newKeyPath = keyStore+"/"+alias;
        if(currentKeyPath!=null && !currentKeyPath.equals(newKeyPath)){
            configurationDAO.updateCaConfiguration(tenantId, keyStore, alias);
            CertificateManager.getInstance().revokeAllIssuedCertificates(RevokeReason
                    .REVOCATION_REASON_CACOMPROMISE.getCode());
        }

    }

    public int getTokenValidity(){
        //todo:read from config
        return CaConstants.DEFAULT_SCEP_TOKEN_VALIDITY;
    }

    public int getTokenLength(){
        //todo:read from config
        return CaConstants.DEFAULT_SCEP_TOKEN_LENGTH;
    }

    public int getScepIssuedCertificateValidity(){
        //todo:read from config
        return CaConstants.DEFAULT_SCEP_CERTIFICATE_VALIDITY;
    }

    private boolean nullSafeEquals(String s1, String s2){
        if(s1==null){
            return s2 == null;
        } else {
            return s1.equals(s2);
        }
    }
}
