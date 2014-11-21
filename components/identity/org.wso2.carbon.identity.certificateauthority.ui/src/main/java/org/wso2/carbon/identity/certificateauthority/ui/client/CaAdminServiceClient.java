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
package org.wso2.carbon.identity.certificateauthority.ui.client;

import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.certificateauthority.common.CertificateStatus;
import org.wso2.carbon.identity.certificateauthority.stub.*;

import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.rmi.RemoteException;
import java.util.Locale;
import java.util.ResourceBundle;

public class CaAdminServiceClient {

    private static final Log log = LogFactory.getLog(CaAdminServiceClient.class);
    private static final String BUNDLE = "org.wso2.carbon.identity.certificateauthority.ui.i18n.Resources";
    private CaAdminServiceStub stub;
    private ResourceBundle bundle;


    /**
     * Instantiates CAAdminServiceClient
     *
     * @param cookie           For session management
     * @param backendServerURL URL of the back end server where CAAdminService is
     *                         running.
     * @param configCtx        ConfigurationContext
     * @throws org.apache.axis2.AxisFault
     */

    public CaAdminServiceClient(String cookie, String backendServerURL,
                                ConfigurationContext configCtx) throws AxisFault {
        String serviceURL = backendServerURL + "CaAdminService";
        stub = new CaAdminServiceStub(configCtx, serviceURL);
        ServiceClient client = stub._getServiceClient();
        Options option = client.getOptions();
        option.setManageSession(true);
        option.setProperty(HTTPConstants.COOKIE_STRING, cookie);
    }


    public CaAdminServiceClient(String cookie,
                                String backendServerURL,
                                ConfigurationContext configCtx,
                                Locale locale) throws AxisFault {
        String serviceURL = backendServerURL + "CaAdminService";
        bundle = ResourceBundle.getBundle(BUNDLE, locale);

        stub = new CaAdminServiceStub(configCtx, serviceURL);
        ServiceClient client = stub._getServiceClient();
        Options option = client.getOptions();
        option.setManageSession(true);
        option.setProperty(HTTPConstants.COOKIE_STRING, cookie);
    }

    /**
     * Returns the list of CSR Files belongs to the tenant
     *
     * @return list of CSR Files
     * @throws AxisFault
     */
    public CsrInfo[] getCSRFileList() throws AxisFault {

        try {
            return stub.getCsrList();
        } catch (Exception e) {
            String message = e.getMessage();
            handleException(e.getMessage(), e);
        }
        return new CsrInfo[0];
    }

    /**
     * Returns the list of keystores
     *
     * @return keystore list
     * @throws AxisFault
     */
    public String[] getKeyStoreList() throws AxisFault {
        try {
            return stub.listKeyAliases();
        } catch (RemoteException e) {
            handleException(e.getMessage(), e);
        } catch (CaAdminServiceCaException e) {
            handleException(e.getMessage(), e);
        }
        return new String[0];
    }

    /**
     * Sign the CSR file with a given serial number and validity period
     *
     * @param serial   serial number of signing CSR
     * @param validity validity period
     */

    public void sign(String serial, int validity) {
        try {
            stub.signCSR(serial, validity);
        } catch (RemoteException e) {
            //todo: exception handling
            e.printStackTrace();
        } catch (CaAdminServiceCaException e) {
            e.printStackTrace();
        }
    }

    /**
     * Reject the CSR file with a given serial number
     *
     * @param serialNo serial number of rejecting CSR
     */
    public void rejectCSR(String serialNo) {
        try {
            stub.rejectCSR(serialNo);
        } catch (RemoteException e) {
            //todo: exception handling
            e.printStackTrace();
        } catch (CaAdminServiceCaException e) {
            e.printStackTrace();
        }
    }

    /**
     * Returns CSR File with a given serial number
     *
     * @return CSR File Serial Number
     * @throws AxisFault
     */
    public CsrInfo getCSRFromSerialNo(String serialNo) throws AxisFault {

        try {
            return stub.getCsr(serialNo);
        } catch (Exception e) {
            String message = e.getMessage();
            handleException(e.getMessage(), e);
        }
        return null;
    }


    /**
     * Returns the list of Certificates issued
     *
     * @return Certificate File List
     * @throws AxisFault
     */
    public CertificateInfo[] getCertificateList() throws AxisFault {

        try {
            return stub.listCertificatesWithStatus(CertificateStatus.ACTIVE.toString());
        } catch (Exception e) {
            String message = e.getMessage();
            handleException(e.getMessage(), e);
        }
        return null;
    }

    /**
     * Revoking a certificate with a given name and a given reason
     *
     * @param serialNo serial number of revoking certificate
     * @param reason   revoke reason
     * @throws AxisFault
     */
    public void revokeCert(String serialNo, int reason) throws AxisFault {
        try {
            stub.revokeCert(serialNo, reason);
        } catch (Exception e) {
            String message = e.getMessage();
            handleException(e.getMessage(), e);
        }

    }

    /**
     * Returns a certificate from a given serial number
     *
     * @param serialNo serial number of certificate
     * @return certificate
     * @throws AxisFault
     */

    public CertificateInfo getCertificateBySerialNo(String serialNo) throws AxisFault {
        try {
            return stub.getCertificate(serialNo);
        } catch (Exception e) {
            String message = e.getMessage();
            handleException(e.getMessage(), e);
        }
        return null;
    }

    /**
     * Returns the list of keyAliases
     *
     * @return keyAlias list
     * @throws AxisFault
     */

    public String[] getListKeyAliases() throws AxisFault {
        try {
            return stub.listKeyAliases();
        } catch (Exception e) {
            handleException(e.getMessage(), e);
        }
        return null;

    }

    /**
     * Returns the revoke reason of a ceritificate with a given serial number
     *
     * @param serialNo serial number of certificate
     * @return revoke reason
     * @throws AxisFault
     */

    public int getRevokeReason(String serialNo) throws AxisFault {
        try {
            return stub.getRevokedReason(serialNo);
        } catch (Exception e) {
            String message = e.getMessage();
            handleException(e.getMessage(), e);
        }
        return 0;
    }

    /**
     * Returns the list of CSR Files queried from a given status
     *
     * @param status
     * @return CSR File list with a given status
     * @throws AxisFault
     */
    public CsrInfo[] getCSRsFromType(String status) throws AxisFault {
        try {
            return stub.getCsrListWithStatus(status);
        } catch (Exception e) {
            String message = e.getMessage();
            handleException(e.getMessage(), e);
        }
        return new CsrInfo[0];
    }

    /**
     * Returns CSR Files queried by a given common name
     *
     * @param commonName common name of the CSR file
     * @return CSR File with a given common name
     * @throws AxisFault
     */
    public CsrInfo[] getCSRsFromCommonName(String commonName) throws AxisFault {
//        try {
//            return stub.getCsrfromCN(commonName);
//        } catch (Exception e) {
//            String message = e.getMessage();
//            handleException(e.getMessage(), e);
//        }
        return new CsrInfo[0];
    }

    /**
     * Get the list of certificates queried from a given status
     *
     * @param status status of the certificate
     * @return list of certificates with a given status
     * @throws AxisFault
     */
    public CertificateInfo[] getCertificatesFromStatus(String status) throws AxisFault {
        try {
            return stub.listCertificatesWithStatus(status);
        } catch (Exception e) {
            String message = e.getMessage();
            handleException(e.getMessage(), e);
        }
        return new CertificateInfo[0];
    }

    public void changeKeyStore(String keyPath) throws AxisFault {
        String[] keyStoreAndAlias = keyPath.split("/");
        if (keyStoreAndAlias.length == 2) {
            try {
                stub.updateSigningKey(keyStoreAndAlias[0],keyStoreAndAlias[1]);
            } catch (Exception e) {
                handleException(e.getMessage(), e);
            }
        }

    }

    public String generateScepToken() throws AxisFault {
        try {
            return stub.generateScepToken();
        } catch (Exception e) {
            handleException(e.getMessage(), e);
        }
        return null;    //returning null, since this is unreachable
    }

    /**
     * Logs and wraps the given exception.
     *
     * @param msg Error message
     * @param e   Exception
     * @throws org.apache.axis2.AxisFault
     */
    private void handleException(String msg, Exception e) throws AxisFault {
        log.error(msg, e);
        throw new AxisFault(msg, e);
    }

}
