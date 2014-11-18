/*
 * Copyright (c) 2005-2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.certificateauthority.data;

public class CaConfig {
    private int tenantId;
    private String keyStore;
    private String alias;

    public CaConfig(int tenantId, String keyStore, String alias) {
        this.tenantId = tenantId;
        this.keyStore = keyStore;
        this.alias = alias;
    }

    public static CaConfig getDefaultConfig(int tenantId) {
        return new CaConfig(tenantId, null, null);
    }

    public int getTenantId() {
        return tenantId;
    }

    public String getKeyStore() {
        return keyStore;
    }

    public String getAlias() {
        return alias;
    }
}
