/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations under the License.
 */

package org.wso2.carbon.identity.analytic.core.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.databridge.agent.DataPublisher;
import org.wso2.carbon.databridge.agent.exception.DataEndpointAgentConfigurationException;
import org.wso2.carbon.databridge.agent.exception.DataEndpointAuthenticationException;
import org.wso2.carbon.databridge.agent.exception.DataEndpointConfigurationException;
import org.wso2.carbon.databridge.agent.exception.DataEndpointException;
import org.wso2.carbon.databridge.commons.Event;
import org.wso2.carbon.databridge.commons.exception.TransportException;
import org.wso2.carbon.identity.analytic.core.Configuration;
import org.wso2.carbon.identity.analytic.core.EventPublisherService;

public class EventPublisherServiceImpl implements EventPublisherService {

    private static Log log = LogFactory.getLog(EventPublisherServiceImpl.class);
    private DataPublisher dataPublisher = null;

    public EventPublisherServiceImpl() {

        Configuration configuration = Configuration.getConfiguration();
        try {
            this.dataPublisher = new DataPublisher("thrift",
                    "tcp://" + configuration.getHostName() + ":" + configuration.getThriftTCPPort(),
                    "ssl://" + configuration.getHostName() + ":" + configuration.getThriftSSLPort(),
                    configuration.getUsername(), configuration.getPassword());
        } catch (DataEndpointAgentConfigurationException e) {
            log.error(e.getMessage(), e);
        } catch (DataEndpointException e) {
            log.error(e.getMessage(), e);
        } catch (DataEndpointConfigurationException e) {
            log.error(e.getMessage(), e);
        } catch (DataEndpointAuthenticationException e) {
            log.error(e.getMessage(), e);
        } catch (TransportException e) {
            log.error(e.getMessage(), e);
        }
    }

    /**
     * publishes the Event to given server.
     *
     * @param event - event object
     */
    @Override
    public void publish(Event event) {

        dataPublisher.publish(event);

    }
}
