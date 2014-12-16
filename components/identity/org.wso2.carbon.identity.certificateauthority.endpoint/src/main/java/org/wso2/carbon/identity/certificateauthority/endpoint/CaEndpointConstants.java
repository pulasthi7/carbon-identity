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

package org.wso2.carbon.identity.certificateauthority.endpoint;

import org.jscep.transport.response.Capability;

import java.util.HashSet;
import java.util.Set;

public class CaEndpointConstants {

    public static final Set<Capability> SCEP_CAPABILITIES;

    static {
        //Set the scep capabilities
        Set<Capability> capabilities = new HashSet<Capability>();
        capabilities.add(Capability.POST_PKI_OPERATION);
        capabilities.add(Capability.SHA_1);
        SCEP_CAPABILITIES = capabilities;
    }
}