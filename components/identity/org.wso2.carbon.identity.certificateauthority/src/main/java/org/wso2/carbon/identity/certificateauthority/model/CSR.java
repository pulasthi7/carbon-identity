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
 * Represents a CSR
 */
public class CSR {
    private String serialNo;
    private Date requestedDate;
    private String status;

    private String commonName;
    private String organization;
    private String department;
    private String city;
    private String country;
    private String state;

    private String userName;
    private String userStoreDomain;
    private String tenantDomain;

    public CSR(String serialNo, Date requestedDate, String status, String commonName,
               String organization, String department, String city, String country,
               String state, String userName, String userStoreDomain, String tenantDomain) {
        this.serialNo = serialNo;
        this.requestedDate = (Date) requestedDate.clone();
        this.status = status;
        this.commonName = commonName;
        this.organization = organization;
        this.department = department;
        this.city = city;
        this.country = country;
        this.state = state;
        this.userName = userName;
        this.userStoreDomain = userStoreDomain;
        this.tenantDomain = tenantDomain;
    }

    /**
     * Get the serial number of the CSR
     *
     * @return
     */
    public String getSerialNo() {
        return serialNo;
    }

    /**
     * Get the CSR's requested date
     *
     * @return
     */
    public Date getRequestedDate() {
        return (Date) requestedDate.clone();
    }

    /**
     * Get the CSR's current status as in {@link org.wso2.carbon.identity.certificateauthority.common.CSRStatus}
     *
     * @return
     */
    public String getStatus() {
        return status;
    }

    /**
     * Get the value of CN field of CSR
     *
     * @return
     */
    public String getCommonName() {
        return commonName;
    }

    /**
     * Get the value of O field in CSR
     *
     * @return
     */
    public String getOrganization() {
        return organization;
    }

    /**
     * Get the value of OU in CSR
     *
     * @return
     */
    public String getDepartment() {
        return department;
    }

    /**
     * Get the value of L in CSR
     *
     * @return
     */
    public String getCity() {
        return city;
    }

    /**
     * Get value of C in CSR
     *
     * @return
     */
    public String getCountry() {
        return country;
    }

    public String getState() {
        return state;
    }

    /**
     * Get the user's name who requested CSR
     *
     * @return
     */
    public String getUserName() {
        return userName;
    }

    /**
     * Get the user store domain of the user
     *
     * @return
     */
    public String getUserStoreDomain() {
        return userStoreDomain;
    }

    /**
     * Get the tenant domain of the user
     *
     * @return
     */
    public String getTenantDomain() {
        return tenantDomain;
    }
}
