package org.wso2.carbon.identity.analytic.core;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.builder.StAXOMBuilder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.base.IdentityException;
import org.wso2.carbon.utils.ServerConstants;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamReader;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;

public class Configuration {

    private static final String CONFIG_FILE_NAME = "global-analytic-config.xml";
    private static String HOST_NAME_ELEMENT = "hostName";
    private static String TCP_PORT_ELEMENT = "binaryTCPPort";
    private static String SSL_PORT_ELEMENT = "binarySSLPort";
    private static String HTTPS_PORT_ELEMENT = "HTTPSPort";
    private static String USERNAME_ELEMENT = "username";
    private static String PASSWORD__ELEMENT = "password";

    private static Configuration configuration = new Configuration();

    private static Log log = LogFactory.getLog(Configuration.class);


    private String hostName;
    private String binaryTCPPort;
    private String binarySSLPort;
    private String httpsPort;
    private String username;
    private String password;

    public static void init() throws IdentityException{

        String carbonHome = System.getProperty(ServerConstants.CARBON_CONFIG_DIR_PATH);
        String path = carbonHome + File.separator + CONFIG_FILE_NAME;
        OMElement configElement = loadConfigXML(path);

        OMElement hostNameElement;
        OMElement tcpPortElement;
        OMElement sslPortElement;
        OMElement httpsPortElement;
        OMElement usernameElement;
        OMElement passwordElement;

        if ((hostNameElement = configElement.getFirstChildWithName(new QName(HOST_NAME_ELEMENT))) == null) {
            throw IdentityException.error("Invalid config element with no host name in " + CONFIG_FILE_NAME);
        }
        if ((tcpPortElement = configElement.getFirstChildWithName(new QName(TCP_PORT_ELEMENT))) == null) {
            throw IdentityException.error("Invalid config element with no TCP port in " +
                    CONFIG_FILE_NAME);
        }
        if ((httpsPortElement = configElement.getFirstChildWithName(new QName(HTTPS_PORT_ELEMENT))) == null) {
            throw IdentityException.error("Invalid config element with no HTTPS port in " +
                    CONFIG_FILE_NAME);
        }
        if ((sslPortElement = configElement.getFirstChildWithName(new QName(SSL_PORT_ELEMENT))) == null) {
            throw IdentityException.error("Invalid config element with no SSL port in " +
                    CONFIG_FILE_NAME);
        }
        if ((usernameElement = configElement.getFirstChildWithName(new QName(USERNAME_ELEMENT))) == null) {
            throw IdentityException.error("Invalid config element with no username in " +
                    CONFIG_FILE_NAME);
        }
        if ((passwordElement = configElement.getFirstChildWithName(new QName(PASSWORD__ELEMENT))) == null) {
            throw IdentityException.error("Invalid config element with no password in " +
                    CONFIG_FILE_NAME);
        }

        configuration.hostName = hostNameElement.getText();
        configuration.binaryTCPPort = tcpPortElement.getText();
        configuration.binarySSLPort = sslPortElement.getText();
        configuration.httpsPort = httpsPortElement.getText();
        configuration.username = usernameElement.getText();
        configuration.password = passwordElement.getText();

    }

    public static Configuration getConfiguration() {

        return configuration;
    }

    private static OMElement loadConfigXML(String path) throws IdentityException {

        BufferedInputStream inputStream = null;
        try {
            inputStream = new BufferedInputStream(new FileInputStream(new File(path)));
            XMLStreamReader parser = XMLInputFactory.newInstance().
                    createXMLStreamReader(inputStream);
            StAXOMBuilder builder = new StAXOMBuilder(parser);
            OMElement omElement = builder.getDocumentElement();
            omElement.build();
            return omElement;
        } catch (FileNotFoundException e) {
            throw IdentityException.error("Configuration file cannot be found in the path : " + path, e);
        } catch (XMLStreamException e) {
            throw IdentityException.error("Invalid XML syntax for configuration file located in the path :" + path, e);
        } finally {
            try {
                if (inputStream != null) {
                    inputStream.close();
                }
            } catch (IOException e) {
                log.error("Can not shutdown the input stream", e);
            }
        }
    }

    public String getHostName() {

        return hostName;
    }

    public String getBinaryTCPPort() {

        return binaryTCPPort;
    }

    public String getBinarySSLPort() {

        return binarySSLPort;
    }

    public String getHttpsPort() {

        return httpsPort;
    }

    public String getUsername() {

        return username;
    }

    public String getPassword() {

        return password;
    }
}
