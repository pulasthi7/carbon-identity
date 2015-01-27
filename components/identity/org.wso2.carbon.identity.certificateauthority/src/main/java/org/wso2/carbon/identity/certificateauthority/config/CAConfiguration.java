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

package org.wso2.carbon.identity.certificateauthority.config;

import org.apache.axiom.om.OMElement;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.ServerConfigurationException;
import org.wso2.carbon.identity.certificateauthority.CAConstants;
import org.wso2.carbon.identity.core.util.IdentityConfigParser;

import javax.xml.namespace.QName;

/**
 * Reads and store the configuration needed for CA.
 * Configurations are read from identity.xml.
 */
public class CAConfiguration {

    private static final String CA_ROOT_ELEMENT = "CertificateAuthority";
    private static final String SCEP_CONF_ELEMENT = "SCEPConfiguration";
    private static final String SCEP_TOKEN_LENGTH_ELEM = "TokenLength";
    private static final String SCEP_TOKEN_VALIDITY_ELEM = "TokenValidity";
    private static final String SCEP_CERTIFICATE_VALIDITY_ELEM = "CertificateValidity";
    private static final Log log = LogFactory.getLog(CAConfiguration.class);
    private static CAConfiguration instance = new CAConfiguration();
    //initializing to default values in case of reading configs fails
    private int scepTokenLength = CAConstants.DEFAULT_SCEP_TOKEN_LENGTH;
    private int scepTokenValidity = CAConstants.DEFAULT_SCEP_TOKEN_VALIDITY;
    private int scepCertificateValidity = CAConstants.DEFAULT_SCEP_CERTIFICATE_VALIDITY;

    private CAConfiguration() {
    }

    /**
     * Gets the instance of the CaConfiguration.
     *
     * @return
     */
    public static CAConfiguration getInstance() {
        return instance;
    }

    /**
     * Reads the configuration from identity.xml and store them. If any of the configs are
     * missing they are initialized to the default values.
     */
    public void initialize() {
        IdentityConfigParser configParser = null;
        try {
            configParser = IdentityConfigParser.getInstance();
        } catch (ServerConfigurationException e) {
            log.error("Error loading identity configurations.", e);
            return;
        }
        OMElement caRootElem = configParser.getConfigElement(CA_ROOT_ELEMENT);
        if (caRootElem == null) {
            log.warn("Certificate Authority configuration was not found in identity.xml, " +
                    "using the default configuration");
            return;
        }
        OMElement scepElement = caRootElem.getFirstChildWithName(new QName(IdentityConfigParser
                .IDENTITY_DEFAULT_NAMESPACE, SCEP_CONF_ELEMENT));
        if (scepElement != null) {
            OMElement tokenLengthElem = scepElement.getFirstChildWithName(new QName
                    (IdentityConfigParser.IDENTITY_DEFAULT_NAMESPACE, SCEP_TOKEN_LENGTH_ELEM));
            if (tokenLengthElem != null) {
                scepTokenLength = Integer.parseInt(tokenLengthElem.getText().trim());
                if (log.isDebugEnabled()) {
                    log.debug("SCEP Token length set to:" + scepTokenLength);
                }
            } else {
                scepTokenLength = CAConstants.DEFAULT_SCEP_TOKEN_LENGTH;
                log.warn("SCEP token length is not set at identity.xml, Using default length:" + scepTokenLength);
            }

            OMElement tokenValidityElem = scepElement.getFirstChildWithName(new QName
                    (IdentityConfigParser.IDENTITY_DEFAULT_NAMESPACE, SCEP_TOKEN_VALIDITY_ELEM));
            if (tokenValidityElem != null) {
                scepTokenValidity = Integer.parseInt(tokenValidityElem.getText().trim());
            } else {
                scepTokenValidity = CAConstants.DEFAULT_SCEP_TOKEN_VALIDITY;
                log.warn("SCEP token validity is not set at identity.xml, " +
                        "Using default validity:" + scepTokenValidity + " ms");
            }

            OMElement certificateValidityElem = scepElement.getFirstChildWithName(new QName
                    (IdentityConfigParser.IDENTITY_DEFAULT_NAMESPACE, SCEP_CERTIFICATE_VALIDITY_ELEM));
            if (certificateValidityElem != null) {
                scepCertificateValidity = Integer.parseInt(certificateValidityElem.getText().trim());
            } else {
                scepCertificateValidity = CAConstants.DEFAULT_SCEP_CERTIFICATE_VALIDITY;
                log.warn("SCEP certificate validity is not set at identity.xml, " +
                        "Using default validity:" + scepCertificateValidity);

            }
        } else {
            log.warn("SCEP configuration element is not found in identity xml, the configuration parameters will " +
                    "use default values");
        }
    }

    /**
     * Get the validity of a generated SCEP token.
     *
     * @return
     */
    public int getTokenValidity() {
        return scepTokenValidity;
    }

    /**
     * Get the length of the SCEP token.
     *
     * @return
     */
    public int getTokenLength() {
        return scepTokenLength;
    }

    /**
     * Get the validity of the certificates that are issued from a SCEP operation.
     *
     * @return
     */
    public int getScepIssuedCertificateValidity() {
        return scepCertificateValidity;
    }

}
