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

package org.wso2.carbon.identity.certificateauthority;

import org.wso2.carbon.base.ServerConfiguration;

/**
 * Constants required by CA.
 */
public class CAConstants {

    static {
        String PORT_OFFSET = "Ports.Offset";
        String HOST_NAME = "HostName";
        int DEFAULT_HTTP_PORT = 9763;
        HTTP_SERVER_URL = "http://" + ServerConfiguration.getInstance().getFirstProperty(HOST_NAME) + ":" +
                //adds the offset defined in the server configs to the default 9763 port
                (Integer.parseInt(ServerConfiguration.getInstance().getFirstProperty(PORT_OFFSET)) + DEFAULT_HTTP_PORT);
    }

    /**
     * The server URL for HTTP transport, used in building OCSP, CRL endpoint extensions.
     */
    public static final String HTTP_SERVER_URL;

    //Constants for CRL
    public static final int CRL_UPDATER_INITIAL_DELAY = 60 * 10;    //10 minutes
    public static final int CRL_UPDATE_INTERVAL = 60 * 60 * 24;     //once a day
    public static final int CRL_NUMBER_INCREMENT = 1;
    public static final int DELTA_CRL_INDICATOR = 1;
    public static final int CRL_INDICATOR = -1;

    //Constants for SCEP operations
    public static final int DEFAULT_SCEP_TOKEN_LENGTH = 10;
    public static final int DEFAULT_SCEP_TOKEN_VALIDITY = 3 * 60 * 60 * 1000;   //3 hrs
    public static final int DEFAULT_SCEP_CERTIFICATE_VALIDITY = 356;
    public static final int MAX_SCEP_TOKEN_RETRIES = 10; //tries to generate an unused token at most this times

    //Constants for String literals
    public static final String X509 = "X.509";
    public static final String SHA1_WITH_RSA = "SHA1withRSA";
    public static final String SHA256_WITH_RSA = "SHA256withRSA";
    public static final String BC_PROVIDER = "BC";
    public static final String UTF_8_CHARSET = "UTF-8";

    //Endpoints
    //Any change to this section should be done in sync with the CA endpoint component
    public static final String CRL_ENDPOINT = "/ca/crl/_t/";
    public static final String OCSP_ENDPOINT = "/ca/ocsp/_t/";
}
