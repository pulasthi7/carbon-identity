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

package org.wso2.carbon.identity.certificateauthority.model;

import java.util.Date;

/**
 * Represents a Certificate
 */
public class Certificate {

    private String serialNo;
    private Date issuedDate;
    private Date expiryDate;
    private String status;
    private String username;
    private String tenantDomain;
    private String userStoreDomain;

    /**
     * Default constructor
     *
     * @param serialNo        The serial no of the certificate
     * @param issuedDate      The issued date of the certificate
     * @param expiryDate      The expiry date of the certificate
     * @param status          The status of the certificate
     * @param username        The username of the user for whom the certificate is issued
     * @param tenantDomain    The tenant domain of the user
     * @param userStoreDomain The user store of the user
     * @see org.wso2.carbon.identity.certificateauthority.common.CertificateStatus
     */
    public Certificate(String serialNo, Date issuedDate, Date expiryDate, String status,
                       String username, String tenantDomain, String userStoreDomain) {
        this.serialNo = serialNo;
        this.issuedDate = (Date) issuedDate.clone();
        this.expiryDate = (Date) expiryDate.clone();
        this.status = status;
        this.username = username;
        this.tenantDomain = tenantDomain;
        this.userStoreDomain = userStoreDomain;
    }

    /**
     * Gets the serial no of the certificate
     *
     * @return
     */
    public String getSerialNo() {
        return serialNo;
    }

    /**
     * Get the certificate issued date
     *
     * @return
     */
    public Date getIssuedDate() {
        return (Date) issuedDate.clone();
    }

    /**
     * Gets the certificate expiry date
     *
     * @return
     */
    public Date getExpiryDate() {
        return (Date) expiryDate.clone();
    }

    /**
     * Get the certificate status
     *
     * @return
     */
    public String getStatus() {
        return status;
    }

    /**
     * Get the username of the user for whom the certificate is issued
     *
     * @return
     */
    public String getUsername() {
        return username;
    }

    /**
     * Get the tenant id of the user
     *
     * @return
     */
    public String getTenantDomain() {
        return tenantDomain;
    }

    /**
     * Get the user domain of the user
     *
     * @return
     */
    public String getUserStoreDomain() {
        return userStoreDomain;
    }
}
