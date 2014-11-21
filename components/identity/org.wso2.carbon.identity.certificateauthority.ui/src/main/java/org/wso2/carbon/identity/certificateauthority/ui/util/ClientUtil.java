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
package org.wso2.carbon.identity.certificateauthority.ui.util;


import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.certificateauthority.stub.CertificateInfo;
import org.wso2.carbon.identity.certificateauthority.stub.CsrInfo;

/**
 *
 */
public class ClientUtil {
    private static final Log log = LogFactory.getLog(ClientUtil.class);

    public static CsrInfo[] doPagingForCsrs(int pageNumber, int itemsPerPage, CsrInfo[] csrs) {

        CsrInfo[] returnedCsrs;

        int startIndex = pageNumber * itemsPerPage;
        int endIndex = (pageNumber + 1) * itemsPerPage;
        if (itemsPerPage < csrs.length) {
            returnedCsrs = new CsrInfo[itemsPerPage];
        } else {
            returnedCsrs = new CsrInfo[csrs.length];
        }
        for (int i = startIndex, j = 0; i < endIndex && i < csrs.length; i++, j++) {
            returnedCsrs[j] = csrs[i];
        }

        return returnedCsrs;
    }

    public static CertificateInfo[] doPagingForCertificates(int pageNumber, int itemsPerPage, CertificateInfo[] certificates) {

        CertificateInfo[] returnedCertificates;

        int startIndex = pageNumber * itemsPerPage;
        int endIndex = (pageNumber + 1) * itemsPerPage;
        if (itemsPerPage < certificates.length) {
            returnedCertificates = new CertificateInfo[itemsPerPage];
        } else {
            returnedCertificates = new CertificateInfo[certificates.length];
        }
        for (int i = startIndex, j = 0; i < endIndex && i < certificates.length; i++, j++) {
            returnedCertificates[j] = certificates[i];
        }

        return returnedCertificates;
    }
}
