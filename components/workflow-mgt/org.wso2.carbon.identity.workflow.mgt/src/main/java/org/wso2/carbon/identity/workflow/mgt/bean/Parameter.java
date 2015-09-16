/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.workflow.mgt.bean;

import java.util.List;

public class Parameter {

    private String workflowId;
    private String paramName;
    private String paramValue;
    private String qName;
    private String holder;

    public Parameter(){}

    public Parameter(String workflowId, String paramName, String paramValue, String qName, String holder) {
        this.workflowId = workflowId;
        this.paramName = paramName;
        this.paramValue = paramValue;
        this.qName = qName;
        this.holder = holder;
    }

    public String getParamName() {
        return paramName;
    }

    public void setParamName(String paramName) {
        this.paramName = paramName;
    }

    public String getParamValue() {
        return paramValue;
    }

    public void setParamValue(String paramValue) {
        this.paramValue = paramValue;
    }

    public String getWorkflowId() {
        return workflowId;
    }

    public void setWorkflowId(String workflowId) {
        this.workflowId = workflowId;
    }

    public String getQName() {
        return qName;
    }

    public void setQName(String qName) {
        this.qName = qName;
    }

    public String getHolder() {
        return holder;
    }

    public void setHolder(String holder) {
        this.holder = holder;
    }

    public static Parameter getParameter(List<Parameter> parameterList, String paramName, String qName, String holder){
        for (Parameter parameter:parameterList){
            if(parameter.getParamName().equals(paramName) && parameter.getQName().equals(qName) &&
               parameter.getHolder().equals(holder)){
                return parameter ;
            }
        }
        return null ;
    }
    public static Parameter getParameter(List<Parameter> parameterList, String paramName, String holder){
        for (Parameter parameter:parameterList){
            if(parameter.getParamName().equals(paramName) && parameter.getQName().equals(paramName) &&
               parameter.getHolder().equals(holder)){
                return parameter ;
            }
        }
        return null ;
    }
}
