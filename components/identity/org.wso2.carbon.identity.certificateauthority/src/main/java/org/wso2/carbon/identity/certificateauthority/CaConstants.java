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

import org.wso2.carbon.base.ServerConfiguration;

public class CaConstants {

    static {
        HTTP_SERVER_URL = "http://" +
                ServerConfiguration.getInstance().getFirstProperty("HostName")+":"+
                //adds the offset defined in the server configs to the default 9763 port
                Integer.parseInt(ServerConfiguration.getInstance().getFirstProperty("Ports" +
                        ".Offset")) + 9763;
    }

    public static final String HTTP_SERVER_URL;

    public static final String CRL_COMMAND = "cmd";
    public static final String REQUEST_TYPE_CRL = "crl";
    public static final String REQUEST_TYPE_DELTA_CRL = "deltacrl";

    public static final String X509 = "X.509";
    public static final int CRL_UPDATER_INITIAL_DELAY = 60 * 10;    //10 minutes
    public static final int CRL_UPDATE_INTERVAL = 60 * 60 * 24;     //once a day

    public static final int DEFAULT_SCEP_TOKEN_LENGTH = 10;
    public static final int DEFAULT_SCEP_TOKEN_VALIDITY = 3 * 60;
    public static final int DEFAULT_SCEP_CERTIFICATE_VALIDITY = 356;

    public static final String SHA256_WITH_RSA_ENCRYPTION = "SHA256WithRSAEncryption";
    public static final String SHA1_WITH_RSA = "SHA1withRSA";
    public static final String SHA256_WITH_RSA = "SHA256withRSA";

    public static final String BC_PROVIDER = "BC";
    public static final String UTF_8_CHARSET = "UTF-8";

    //Configs from identity.xml
    public static final String CA_ROOT_ELEMENT = "CertificateAuthority";
    public static final String SCEP_CONF_PROVIDER_ELEMENT = "ScepConfigurationProvider";

    //Endpoints
    //Any change to this section should be done in sync with the CA endpoint component
    public static final String CRL_ENDPOINT = "/ca/crl/_t/";
    public static final String OCSP_ENDPOINT = "/ca/ocsp/_t/";
}
