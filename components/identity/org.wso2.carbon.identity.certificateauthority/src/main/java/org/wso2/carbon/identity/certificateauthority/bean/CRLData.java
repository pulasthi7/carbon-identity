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

package org.wso2.carbon.identity.certificateauthority.bean;

import java.util.Date;

/**
 * Represents a CRL.
 */
public class CRLData {

    private Date thisUpdate;
    private Date nextUpdate;
    private String base64Crl;
    private int tenantId;
    private int crlNumber;
    private int deltaCrlIndicator;

    /**
     * Constructs CRLData object.
     *
     * @param thisUpdate        The time the CRL was updated
     * @param nextUpdate        The time the next CRL will be updated
     * @param base64Crl         The base 64 encoded crl
     * @param tenantId          The CA's tenant Id
     * @param crlNumber         The CRL number
     * @param deltaCrlIndicator Identifies delta CRL and CRLs
     */
    public CRLData(Date thisUpdate, Date nextUpdate, String base64Crl, int tenantId, int crlNumber,
                   int deltaCrlIndicator) {
        if (crlNumber < 0) {
            throw new IllegalArgumentException("CRL Number cannot be negative, given:" + crlNumber);
        }
        this.thisUpdate = (Date) thisUpdate.clone();
        this.nextUpdate = (Date) nextUpdate.clone();
        this.base64Crl = base64Crl;
        this.tenantId = tenantId;
        this.crlNumber = crlNumber;
        this.deltaCrlIndicator = deltaCrlIndicator;
    }

    /**
     * Retrieves the CRL number.
     *
     * @return
     */
    public int getCrlNumber() {
        return crlNumber;
    }

    /**
     * Retrieves the delta CRL indicator.
     *
     * @return
     */
    public int getDeltaCrlIndicator() {
        return deltaCrlIndicator;
    }

    /**
     * Retrieves the CA's tenant id.
     *
     * @return
     */
    public int getTenantId() {
        return tenantId;
    }

    /**
     * Retrieves the next update date.
     *
     * @return
     */
    public Date getNextUpdate() {
        return (Date) nextUpdate.clone();
    }

    /**
     * Retrieves the current update date.
     *
     * @return
     */
    public Date getThisUpdate() {
        return (Date) thisUpdate.clone();
    }

    /**
     * Retrieves the Base 64 encoded CRL.
     *
     * @return
     */
    public String getBase64Crl() {
        return base64Crl;
    }
}
