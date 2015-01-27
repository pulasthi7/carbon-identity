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

package org.wso2.carbon.identity.certificateauthority.services;

import org.bouncycastle.cert.ocsp.OCSPReq;
import org.bouncycastle.cert.ocsp.OCSPResp;
import org.wso2.carbon.identity.certificateauthority.CAException;

public interface OCSPService {

    /**
     * handles the OCSP requests
     *
     * @param req          The OCSP request
     * @param tenantDomain The tenant domain of the CA for whom the request is made
     * @return The OCSP response
     * @throws org.wso2.carbon.identity.certificateauthority.CAException
     */
    public OCSPResp handleOCSPRequest(OCSPReq req, String tenantDomain) throws CAException;
}
