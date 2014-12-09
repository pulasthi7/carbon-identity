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

package org.wso2.carbon.identity.certificateauthority.data;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import java.util.Date;

/**
 * Represents a CRL
 */
public class CrlData {
    private Date thisUpdate;
    private Date nextUpdate;
    private String base64Crl;
    private int tenantID;
    private int crlNumber;
    private int deltaCrlIndicator;

    public CrlData(Date thisUpdate, Date nextUpdate, String base64Crl, int tenantID,
                   int crlNumber, int deltaCrlIndicator) {
        this.thisUpdate = (Date) thisUpdate.clone();
        this.nextUpdate = (Date) nextUpdate.clone();
        this.base64Crl = base64Crl;
        this.tenantID = tenantID;
        this.crlNumber = crlNumber;
        this.deltaCrlIndicator = deltaCrlIndicator;
    }

    public int getCrlNumber() {
        return crlNumber;
    }

    public int getDeltaCrlIndicator() {
        return deltaCrlIndicator;
    }

    public int getTenantID() {
        return tenantID;
    }

    public Date getNextUpdate() {
        return (Date) nextUpdate.clone();
    }

    public Date getThisUpdate() {
        return (Date) thisUpdate.clone();
    }

    public String getBase64Crl() {
        return base64Crl;
    }
}
