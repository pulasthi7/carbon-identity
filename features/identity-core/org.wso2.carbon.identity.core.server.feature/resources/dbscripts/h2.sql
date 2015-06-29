CREATE TABLE IF NOT EXISTS IDN_BASE_TABLE (
            PRODUCT_NAME VARCHAR (20),
            PRIMARY KEY (PRODUCT_NAME)
);

INSERT INTO IDN_BASE_TABLE values ('WSO2 Identity Server');

CREATE TABLE IF NOT EXISTS IDN_OAUTH_CONSUMER_APPS (
            CONSUMER_KEY VARCHAR (512),
            CONSUMER_SECRET VARCHAR (512),
            USERNAME VARCHAR (255),
            TENANT_ID INTEGER DEFAULT 0,
            APP_NAME VARCHAR (255),
            OAUTH_VERSION VARCHAR (128),
            CALLBACK_URL VARCHAR (1024),
            GRANT_TYPES VARCHAR (1024),
            PRIMARY KEY (CONSUMER_KEY)
);

CREATE TABLE IF NOT EXISTS IDN_OAUTH1A_REQUEST_TOKEN (
            REQUEST_TOKEN VARCHAR (512),
            REQUEST_TOKEN_SECRET VARCHAR (512),
            CONSUMER_KEY VARCHAR (512),
            CALLBACK_URL VARCHAR (1024),
            SCOPE VARCHAR(2048),
            AUTHORIZED VARCHAR (128),
            OAUTH_VERIFIER VARCHAR (512),
            AUTHZ_USER VARCHAR (512),
            PRIMARY KEY (REQUEST_TOKEN),
            FOREIGN KEY (CONSUMER_KEY) REFERENCES IDN_OAUTH_CONSUMER_APPS(CONSUMER_KEY) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS IDN_OAUTH1A_ACCESS_TOKEN (
            ACCESS_TOKEN VARCHAR (512),
            ACCESS_TOKEN_SECRET VARCHAR (512),
            CONSUMER_KEY VARCHAR (512),
            SCOPE VARCHAR(2048),
            AUTHZ_USER VARCHAR (512),
            PRIMARY KEY (ACCESS_TOKEN),
            FOREIGN KEY (CONSUMER_KEY) REFERENCES IDN_OAUTH_CONSUMER_APPS(CONSUMER_KEY) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS IDN_OAUTH2_ACCESS_TOKEN (
      TOKEN_ID VARCHAR (255),
			ACCESS_TOKEN VARCHAR (255),
			REFRESH_TOKEN VARCHAR (255),
			CONSUMER_KEY VARCHAR (255),
			AUTHZ_USER VARCHAR (255),
			USER_TYPE VARCHAR (25),
			TIME_CREATED TIMESTAMP DEFAULT 0,
			REFRESH_TOKEN_TIME_CREATED TIMESTAMP DEFAULT 0,
			VALIDITY_PERIOD BIGINT,
			REFRESH_TOKEN_VALIDITY_PERIOD BIGINT,
			TOKEN_SCOPE_HASH VARCHAR (32),
			TOKEN_STATE VARCHAR (25) DEFAULT 'ACTIVE',
			TOKEN_STATE_ID VARCHAR (256) DEFAULT 'NONE',
			PRIMARY KEY (TOKEN_ID),
	        FOREIGN KEY (CONSUMER_KEY) REFERENCES IDN_OAUTH_CONSUMER_APPS(CONSUMER_KEY) ON DELETE CASCADE,
	        CONSTRAINT CON_APP_KEY UNIQUE (CONSUMER_KEY,AUTHZ_USER,USER_TYPE,TOKEN_SCOPE_HASH,TOKEN_STATE,TOKEN_STATE_ID)
);

CREATE TABLE IF NOT EXISTS IDN_OAUTH2_AUTHORIZATION_CODE (
            AUTHORIZATION_CODE VARCHAR (512),
            CONSUMER_KEY VARCHAR (512),
	          CALLBACK_URL VARCHAR (1024),
            SCOPE VARCHAR(2048),
            AUTHZ_USER VARCHAR (512),
            TIME_CREATED TIMESTAMP,
			      VALIDITY_PERIOD BIGINT,
	          STATE VARCHAR (25) DEFAULT 'ACTIVE',
            TOKEN_ID VARCHAR(255),
            PRIMARY KEY (AUTHORIZATION_CODE),
            FOREIGN KEY (CONSUMER_KEY) REFERENCES IDN_OAUTH_CONSUMER_APPS(CONSUMER_KEY) ON DELETE CASCADE
);

CREATE INDEX IDX_AT_CK_AU ON IDN_OAUTH2_ACCESS_TOKEN(CONSUMER_KEY, AUTHZ_USER, TOKEN_STATE, USER_TYPE);

CREATE TABLE IF NOT EXISTS IDN_OAUTH2_ACCESS_TOKEN_SCOPE_ASSOCIATION (
            TOKEN_ID VARCHAR (255),
            TOKEN_SCOPE VARCHAR (60),
            PRIMARY KEY (TOKEN_ID, TOKEN_SCOPE),
            FOREIGN KEY (TOKEN_ID) REFERENCES IDN_OAUTH2_ACCESS_TOKEN(TOKEN_ID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS IDN_OAUTH2_SCOPE (
            SCOPE_ID INTEGER NOT NULL AUTO_INCREMENT,
            SCOPE_KEY VARCHAR(100) NOT NULL,
            NAME VARCHAR(255) NULL,
            DESCRIPTION VARCHAR(512) NULL,
            TENANT_ID INTEGER NOT NULL DEFAULT 0,
	    ROLES VARCHAR (500) NULL,
            PRIMARY KEY (SCOPE_ID)
);

CREATE TABLE IF NOT EXISTS IDN_OAUTH2_RESOURCE_SCOPE (
            RESOURCE_PATH VARCHAR(255) NOT NULL,
            SCOPE_ID INTEGER (11) NOT NULL,
            PRIMARY KEY (RESOURCE_PATH),
            FOREIGN KEY (SCOPE_ID) REFERENCES IDN_OAUTH2_SCOPE (SCOPE_ID)
);

CREATE TABLE IF NOT EXISTS IDN_SCIM_GROUP (
            ID INTEGER GENERATED ALWAYS AS IDENTITY,
            TENANT_ID INTEGER NOT NULL,
            ROLE_NAME VARCHAR(255) NOT NULL,
            ATTR_NAME VARCHAR(1024) NOT NULL,
			ATTR_VALUE VARCHAR(1024),
            PRIMARY KEY (ID)
);

CREATE TABLE IF NOT EXISTS IDN_SCIM_PROVIDER (
            CONSUMER_ID VARCHAR(255) NOT NULL,
            PROVIDER_ID VARCHAR(255) NOT NULL,
            USER_NAME VARCHAR(255) NOT NULL,
            USER_PASSWORD VARCHAR(255) NOT NULL,
            USER_URL VARCHAR(1024) NOT NULL,
			GROUP_URL VARCHAR(1024),
			BULK_URL VARCHAR(1024),
            PRIMARY KEY (CONSUMER_ID,PROVIDER_ID)
);

CREATE TABLE IF NOT EXISTS IDN_OPENID_REMEMBER_ME (
            USER_NAME VARCHAR(255) NOT NULL,
            TENANT_ID INTEGER DEFAULT 0,
            COOKIE_VALUE VARCHAR(1024),
            CREATED_TIME TIMESTAMP,
            PRIMARY KEY (USER_NAME, TENANT_ID)
);

CREATE TABLE IF NOT EXISTS IDN_OPENID_USER_RPS (
			USER_NAME VARCHAR(255) NOT NULL,
			TENANT_ID INTEGER DEFAULT 0,
			RP_URL VARCHAR(255) NOT NULL,
			TRUSTED_ALWAYS VARCHAR(128) DEFAULT 'FALSE',
			LAST_VISIT DATE NOT NULL,
			VISIT_COUNT INTEGER DEFAULT 0,
			DEFAULT_PROFILE_NAME VARCHAR(255) DEFAULT 'DEFAULT',
			PRIMARY KEY (USER_NAME, TENANT_ID, RP_URL)
);

CREATE TABLE IF NOT EXISTS IDN_OPENID_ASSOCIATIONS (
			HANDLE VARCHAR(255) NOT NULL,
			ASSOC_TYPE VARCHAR(255) NOT NULL,
			EXPIRE_IN TIMESTAMP NOT NULL,
			MAC_KEY VARCHAR(255) NOT NULL,
			ASSOC_STORE VARCHAR(128) DEFAULT 'SHARED',
			PRIMARY KEY (HANDLE)
);

CREATE TABLE IDN_STS_STORE (
            ID INTEGER AUTO_INCREMENT,
            TOKEN_ID VARCHAR(255) NOT NULL,
            TOKEN_CONTENT BLOB NOT NULL,
            CREATE_DATE TIMESTAMP NOT NULL,
            EXPIRE_DATE TIMESTAMP NOT NULL,
            STATE INTEGER DEFAULT 0,
            PRIMARY KEY (ID)
);

CREATE TABLE IDN_IDENTITY_USER_DATA (
            TENANT_ID INTEGER DEFAULT -1234,
            USER_NAME VARCHAR(255) NOT NULL,
            DATA_KEY VARCHAR(255) NOT NULL,
            DATA_VALUE VARCHAR(255),
            PRIMARY KEY (TENANT_ID, USER_NAME, DATA_KEY)
);

CREATE TABLE IDN_IDENTITY_META_DATA (
            USER_NAME VARCHAR(255) NOT NULL,
            TENANT_ID INTEGER DEFAULT -1234,
            METADATA_TYPE VARCHAR(255) NOT NULL,
            METADATA VARCHAR(255) NOT NULL,
            VALID VARCHAR(255) NOT NULL,
            PRIMARY KEY (TENANT_ID, USER_NAME, METADATA_TYPE,METADATA)
);

CREATE TABLE IF NOT EXISTS IDN_THRIFT_SESSION (
            SESSION_ID VARCHAR(255) NOT NULL,
            USER_NAME VARCHAR(255) NOT NULL,
            CREATED_TIME VARCHAR(255) NOT NULL,
            LAST_MODIFIED_TIME VARCHAR(255) NOT NULL,
            PRIMARY KEY (SESSION_ID)
);

CREATE TABLE IDN_AUTH_SESSION_STORE (
		        SESSION_ID VARCHAR (100) DEFAULT NULL,
		        SESSION_TYPE VARCHAR(100) DEFAULT NULL,
		        SESSION_OBJECT BLOB,
		        TIME_CREATED TIMESTAMP,
		        PRIMARY KEY (SESSION_ID, SESSION_TYPE)
);

CREATE  TABLE IF NOT EXISTS CA_CERTIFICATE_STORE (
    `SERIAL_NO` VARCHAR(45) NOT NULL ,
    `UM_DOMAIN_NAME` VARCHAR(45) NULL ,
    `PUBLIC_CERTIFICATE` BLOB NULL ,
    `STATUS` VARCHAR(45) NULL DEFAULT 'ACTIVE',
    `ISSUED_DATE` DATE NULL ,
    `EXPIRY_DATE` DATE NULL ,
    `TENANT_ID` INTEGER NULL ,
    `USER_NAME` VARCHAR(45) NULL ,
    PRIMARY KEY (`SERIAL_NO`)
);

CREATE  TABLE IF NOT EXISTS `CA_CSR_STORE` (
    `COMMON_NAME` VARCHAR(100) NOT NULL,
    `ORGANIZATION` VARCHAR(100),
    `USER_NAME` VARCHAR(255) NULL,
    `TENANT_ID` INTEGER DEFAULT 0,
    `CSR_CONTENT` BLOB NOT NULL ,
    `STATUS` VARCHAR(45) NULL DEFAULT 'pending' COMMENT 'This columns will have the values of arpproved, rejected or pending\n' ,
    `REQUESTED_DATE` DATE NOT NULL ,
    `SERIAL_NO` VARCHAR(100) NOT NULL ,
    `UM_DOMAIN_NAME` VARCHAR(45) NULL ,
    `TRANSACTION_ID` VARCHAR(130) NULL,
    PRIMARY KEY (`SERIAL_NO`)
);

CREATE  TABLE IF NOT EXISTS `CA_REVOKED_CERTIFICATES` (
    `SERIAL_NO` VARCHAR(45) NOT NULL ,
    `REVOKED_DATE` DATE NULL ,
    `TENANT_ID` INTEGER NULL ,
    `REASON` INTEGER NULL ,
    PRIMARY KEY (`SERIAL_NO`)
);

CREATE  TABLE IF NOT EXISTS `CA_CRL_STORE` (
    `CRL_NUMBER` INTEGER NOT NULL,
    `BASE64CRL` LONGTEXT NOT NULL,
    `THIS_UPDATE` DATE NULL ,
    `NEXT_UPDATE` DATE NULL ,
    `TENANT_ID` INTEGER NULL ,
    `DELTA_CRL_INDICATOR` INTEGER NULL ,
    PRIMARY KEY (`CRL_NUMBER`,`TENANT_ID`)
);

CREATE  TABLE IF NOT EXISTS `CA_CONFIGURATIONS` (
    `TENANT_ID` INTEGER NOT NULL ,
    `KEY_STORE` VARCHAR(45) NULL ,
    `ALIAS` VARCHAR(45) ,
    PRIMARY KEY (`TENANT_ID`)
);
CREATE TABLE IF NOT EXISTS SP_APP (
            ID INTEGER NOT NULL AUTO_INCREMENT,
            TENANT_ID INTEGER NOT NULL,
	    	APP_NAME VARCHAR (255) NOT NULL ,
	    	USER_STORE VARCHAR (255) NOT NULL,
            USERNAME VARCHAR (255) NOT NULL ,
            DESCRIPTION VARCHAR (1024),
	    	ROLE_CLAIM VARCHAR (512),
            AUTH_TYPE VARCHAR (255) NOT NULL,
	    	PROVISIONING_USERSTORE_DOMAIN VARCHAR (512),
	    	IS_LOCAL_CLAIM_DIALECT CHAR(1) DEFAULT '1',
	    	IS_SEND_LOCAL_SUBJECT_ID CHAR(1) DEFAULT '0',
	    	IS_SEND_AUTH_LIST_OF_IDPS CHAR(1) DEFAULT '0',
	    	SUBJECT_CLAIM_URI VARCHAR (512),
	    	IS_SAAS_APP CHAR(1) DEFAULT '0',
            PRIMARY KEY (ID));

ALTER TABLE SP_APP ADD CONSTRAINT APPLICATION_NAME_CONSTRAINT UNIQUE(APP_NAME, TENANT_ID);

CREATE TABLE IF NOT EXISTS SP_INBOUND_AUTH (
            ID INTEGER NOT NULL AUTO_INCREMENT,
	     	TENANT_ID INTEGER NOT NULL,
	     	INBOUND_AUTH_KEY VARCHAR (255) NOT NULL,
            INBOUND_AUTH_TYPE VARCHAR (255) NOT NULL,
            PROP_NAME VARCHAR (255),
            PROP_VALUE VARCHAR (1024) ,
	     	APP_ID INTEGER NOT NULL,
            PRIMARY KEY (ID));

ALTER TABLE SP_INBOUND_AUTH ADD CONSTRAINT APPLICATION_ID_CONSTRAINT FOREIGN KEY (APP_ID) REFERENCES SP_APP (ID) ON DELETE CASCADE;

CREATE TABLE IF NOT EXISTS SP_AUTH_STEP (
            ID INTEGER NOT NULL AUTO_INCREMENT,
            TENANT_ID INTEGER NOT NULL,
	     	STEP_ORDER INTEGER DEFAULT 1,
            APP_ID INTEGER NOT NULL ,
            IS_SUBJECT_STEP CHAR(1) DEFAULT '0',
            IS_ATTRIBUTE_STEP CHAR(1) DEFAULT '0',
            PRIMARY KEY (ID));

ALTER TABLE SP_AUTH_STEP ADD CONSTRAINT APPLICATION_ID_CONSTRAINT_STEP FOREIGN KEY (APP_ID) REFERENCES SP_APP (ID) ON DELETE CASCADE;

CREATE TABLE IF NOT EXISTS SP_FEDERATED_IDP (
            ID INTEGER NOT NULL,
            TENANT_ID INTEGER NOT NULL,
            AUTHENTICATOR_ID INTEGER NOT NULL,
            PRIMARY KEY (ID, AUTHENTICATOR_ID));

ALTER TABLE SP_FEDERATED_IDP ADD CONSTRAINT STEP_ID_CONSTRAINT FOREIGN KEY (ID) REFERENCES SP_AUTH_STEP (ID) ON DELETE CASCADE;

CREATE TABLE IF NOT EXISTS SP_CLAIM_MAPPING (
	    	ID INTEGER NOT NULL AUTO_INCREMENT,
	    	TENANT_ID INTEGER NOT NULL,
	    	IDP_CLAIM VARCHAR (512) NOT NULL ,
            SP_CLAIM VARCHAR (512) NOT NULL ,
	   		APP_ID INTEGER NOT NULL,
	    	IS_REQUESTED VARCHAR(128) DEFAULT '0',
	    	DEFAULT_VALUE VARCHAR(255),
            PRIMARY KEY (ID));

ALTER TABLE SP_CLAIM_MAPPING ADD CONSTRAINT CLAIMID_APPID_CONSTRAINT FOREIGN KEY (APP_ID) REFERENCES SP_APP (ID) ON DELETE CASCADE;

CREATE TABLE IF NOT EXISTS SP_ROLE_MAPPING (
	    	ID INTEGER NOT NULL AUTO_INCREMENT,
	    	TENANT_ID INTEGER NOT NULL,
	    	IDP_ROLE VARCHAR (255) NOT NULL ,
            SP_ROLE VARCHAR (255) NOT NULL ,
	    	APP_ID INTEGER NOT NULL,
            PRIMARY KEY (ID));

ALTER TABLE SP_ROLE_MAPPING ADD CONSTRAINT ROLEID_APPID_CONSTRAINT FOREIGN KEY (APP_ID) REFERENCES SP_APP (ID) ON DELETE CASCADE;

CREATE TABLE IF NOT EXISTS SP_REQ_PATH_AUTHENTICATOR (
	    	ID INTEGER NOT NULL AUTO_INCREMENT,
	    	TENANT_ID INTEGER NOT NULL,
	    	AUTHENTICATOR_NAME VARCHAR (255) NOT NULL ,
	    	APP_ID INTEGER NOT NULL,
            PRIMARY KEY (ID));

ALTER TABLE SP_REQ_PATH_AUTHENTICATOR ADD CONSTRAINT REQ_AUTH_APPID_CONSTRAINT FOREIGN KEY (APP_ID) REFERENCES SP_APP (ID) ON DELETE CASCADE;

CREATE TABLE IF NOT EXISTS SP_PROVISIONING_CONNECTOR (
	    	ID INTEGER NOT NULL AUTO_INCREMENT,
	    	TENANT_ID INTEGER NOT NULL,
            IDP_NAME VARCHAR (255) NOT NULL ,
	    	CONNECTOR_NAME VARCHAR (255) NOT NULL ,
	    	APP_ID INTEGER NOT NULL,
	    	IS_JIT_ENABLED CHAR(1) NOT NULL DEFAULT '0',
		BLOCKING CHAR(1) NOT NULL DEFAULT '0',
            PRIMARY KEY (ID));

ALTER TABLE SP_PROVISIONING_CONNECTOR ADD CONSTRAINT PRO_CONNECTOR_APPID_CONSTRAINT FOREIGN KEY (APP_ID) REFERENCES SP_APP (ID) ON DELETE CASCADE;

CREATE TABLE IF NOT EXISTS IDP (
			ID INTEGER AUTO_INCREMENT,
			TENANT_ID INTEGER,
			NAME VARCHAR(254) NOT NULL,
			IS_ENABLED CHAR(1) NOT NULL DEFAULT '1',
			IS_PRIMARY CHAR(1) NOT NULL DEFAULT '0',
			HOME_REALM_ID VARCHAR(254),
			IMAGE MEDIUMBLOB,
			CERTIFICATE BLOB,
			ALIAS VARCHAR(254),
			INBOUND_PROV_ENABLED CHAR (1) NOT NULL DEFAULT '0',
			INBOUND_PROV_USER_STORE_ID VARCHAR(254),
 			USER_CLAIM_URI VARCHAR(254),
 			ROLE_CLAIM_URI VARCHAR(254),
  			DESCRIPTION VARCHAR (1024),
 			DEFAULT_AUTHENTICATOR_NAME VARCHAR(254),
 			DEFAULT_PRO_CONNECTOR_NAME VARCHAR(254),
 			PROVISIONING_ROLE VARCHAR(128),
 			IS_FEDERATION_HUB CHAR(1) NOT NULL DEFAULT '0',
 			IS_LOCAL_CLAIM_DIALECT CHAR(1) NOT NULL DEFAULT '0',
	                DISPLAY_NAME VARCHAR(255),
			PRIMARY KEY (ID),
			UNIQUE (TENANT_ID, NAME));

INSERT INTO IDP (TENANT_ID, NAME, HOME_REALM_ID) VALUES (-1234, 'LOCAL', 'localhost');

CREATE TABLE IF NOT EXISTS IDP_ROLE (
			ID INTEGER AUTO_INCREMENT,
			IDP_ID INTEGER,
			TENANT_ID INTEGER,
			ROLE VARCHAR(254),
			PRIMARY KEY (ID),
			UNIQUE (IDP_ID, ROLE),
			FOREIGN KEY (IDP_ID) REFERENCES IDP(ID) ON DELETE CASCADE);

CREATE TABLE IF NOT EXISTS IDP_ROLE_MAPPING (
			ID INTEGER AUTO_INCREMENT,
			IDP_ROLE_ID INTEGER,
			TENANT_ID INTEGER,
			USER_STORE_ID VARCHAR (253),
			LOCAL_ROLE VARCHAR(253),
			PRIMARY KEY (ID),
			UNIQUE (IDP_ROLE_ID, TENANT_ID, USER_STORE_ID, LOCAL_ROLE),
			FOREIGN KEY (IDP_ROLE_ID) REFERENCES IDP_ROLE(ID) ON DELETE CASCADE);

CREATE TABLE IF NOT EXISTS IDP_CLAIM (
			ID INTEGER AUTO_INCREMENT,
			IDP_ID INTEGER,
			TENANT_ID INTEGER,
			CLAIM VARCHAR(254),
			PRIMARY KEY (ID),
			UNIQUE (IDP_ID, CLAIM),
			FOREIGN KEY (IDP_ID) REFERENCES IDP(ID) ON DELETE CASCADE);

CREATE TABLE IF NOT EXISTS IDP_CLAIM_MAPPING (
			ID INTEGER AUTO_INCREMENT,
			IDP_CLAIM_ID INTEGER,
			TENANT_ID INTEGER,
			LOCAL_CLAIM VARCHAR(253),
		    	DEFAULT_VALUE VARCHAR(255),
			IS_REQUESTED VARCHAR(128) DEFAULT '0',
			PRIMARY KEY (ID),
			UNIQUE (IDP_CLAIM_ID, TENANT_ID, LOCAL_CLAIM),
			FOREIGN KEY (IDP_CLAIM_ID) REFERENCES IDP_CLAIM(ID) ON DELETE CASCADE);

CREATE TABLE IF NOT EXISTS IDP_AUTHENTICATOR (
            ID INTEGER AUTO_INCREMENT,
            TENANT_ID INTEGER,
            IDP_ID INTEGER,
            NAME VARCHAR(255) NOT NULL,
            IS_ENABLED CHAR (1) DEFAULT '1',
            DISPLAY_NAME VARCHAR(255),
            PRIMARY KEY (ID),
            UNIQUE (TENANT_ID, IDP_ID, NAME),
            FOREIGN KEY (IDP_ID) REFERENCES IDP(ID) ON DELETE CASCADE);

INSERT INTO IDP_AUTHENTICATOR (TENANT_ID, IDP_ID, NAME) VALUES (-1234, 1, 'samlsso');
INSERT INTO IDP_AUTHENTICATOR (TENANT_ID, IDP_ID, NAME) VALUES (-1234, 1, 'IDPProperties');

CREATE TABLE IF NOT EXISTS IDP_AUTHENTICATOR_PROPERTY (
            ID INTEGER AUTO_INCREMENT,
            TENANT_ID INTEGER,
            AUTHENTICATOR_ID INTEGER,
            PROPERTY_KEY VARCHAR(255) NOT NULL,
            PROPERTY_VALUE VARCHAR(2047),
            IS_SECRET CHAR (1) DEFAULT '0',
            PRIMARY KEY (ID),
            UNIQUE (TENANT_ID, AUTHENTICATOR_ID, PROPERTY_KEY),
            FOREIGN KEY (AUTHENTICATOR_ID) REFERENCES IDP_AUTHENTICATOR(ID) ON DELETE CASCADE);

INSERT INTO  IDP_AUTHENTICATOR_PROPERTY (TENANT_ID, AUTHENTICATOR_ID, PROPERTY_KEY,PROPERTY_VALUE, IS_SECRET ) VALUES (-1234, 1 , 'IdPEntityId', 'localhost', '0');

CREATE TABLE IF NOT EXISTS IDP_PROVISIONING_CONFIG (
            ID INTEGER AUTO_INCREMENT,
            TENANT_ID INTEGER,
            IDP_ID INTEGER,
            PROVISIONING_CONNECTOR_TYPE VARCHAR(255) NOT NULL,
            IS_ENABLED CHAR (1) DEFAULT '0',
            IS_BLOCKING CHAR (1) DEFAULT '0',
            PRIMARY KEY (ID),
            UNIQUE (TENANT_ID, IDP_ID, PROVISIONING_CONNECTOR_TYPE),
            FOREIGN KEY (IDP_ID) REFERENCES IDP(ID) ON DELETE CASCADE);

CREATE TABLE IF NOT EXISTS IDP_PROV_CONFIG_PROPERTY (
            ID INTEGER AUTO_INCREMENT,
            TENANT_ID INTEGER,
            PROVISIONING_CONFIG_ID INTEGER,
            PROPERTY_KEY VARCHAR(255) NOT NULL,
            PROPERTY_VALUE VARCHAR(2048),
            PROPERTY_BLOB_VALUE BLOB,
            PROPERTY_TYPE CHAR(32) NOT NULL,
            IS_SECRET CHAR (1) DEFAULT '0',
            PRIMARY KEY (ID),
            UNIQUE (TENANT_ID, PROVISIONING_CONFIG_ID, PROPERTY_KEY),
            FOREIGN KEY (PROVISIONING_CONFIG_ID) REFERENCES IDP_PROVISIONING_CONFIG(ID) ON DELETE CASCADE);

CREATE TABLE IF NOT EXISTS IDP_PROVISIONING_ENTITY (
            ID INTEGER AUTO_INCREMENT,
            PROVISIONING_CONFIG_ID INTEGER,
            ENTITY_TYPE VARCHAR(255) NOT NULL,
            ENTITY_LOCAL_USERSTORE VARCHAR(255) NOT NULL,
            ENTITY_NAME VARCHAR(255) NOT NULL,
            ENTITY_VALUE VARCHAR(255),
            TENANT_ID INTEGER,
            PRIMARY KEY (ID),
            UNIQUE (ENTITY_TYPE, TENANT_ID, ENTITY_LOCAL_USERSTORE, ENTITY_NAME, PROVISIONING_CONFIG_ID),
            UNIQUE (PROVISIONING_CONFIG_ID, ENTITY_TYPE, ENTITY_VALUE),
            FOREIGN KEY (PROVISIONING_CONFIG_ID) REFERENCES IDP_PROVISIONING_CONFIG(ID) ON DELETE CASCADE);

CREATE TABLE IF NOT EXISTS IDP_LOCAL_CLAIM (
            ID INTEGER AUTO_INCREMENT,
            TENANT_ID INTEGER,
            IDP_ID INTEGER,
            CLAIM_URI VARCHAR(255) NOT NULL,
            DEFAULT_VALUE VARCHAR(255),
	    IS_REQUESTED VARCHAR(128) DEFAULT '0',
            PRIMARY KEY (ID),
            UNIQUE (TENANT_ID, IDP_ID, CLAIM_URI),
            FOREIGN KEY (IDP_ID) REFERENCES IDP(ID) ON DELETE CASCADE);

CREATE TABLE IF NOT EXISTS IDN_ASSOCIATED_ID (
            ID INTEGER AUTO_INCREMENT,
	    IDP_USER_ID VARCHAR(255) NOT NULL,
            TENANT_ID INTEGER DEFAULT -1234,
	    IDP_ID INTEGER NOT NULL,
            DOMAIN_NAME VARCHAR(255) NOT NULL,
 	    USER_NAME VARCHAR(255) NOT NULL,
	    PRIMARY KEY (ID),
            UNIQUE(IDP_USER_ID, TENANT_ID, IDP_ID),
            FOREIGN KEY (IDP_ID) REFERENCES IDP(ID) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS IDN_USER_ACCOUNT_ASSOCIATION (
            ASSOCIATION_KEY VARCHAR(255) NOT NULL,
            TENANT_ID INTEGER,
            DOMAIN_NAME VARCHAR(255) NOT NULL,
            USER_NAME VARCHAR(255) NOT NULL,
            PRIMARY KEY (TENANT_ID, DOMAIN_NAME, USER_NAME));

CREATE TABLE IF NOT EXISTS FIDO_DEVICE_STORE (
        TENANT_ID INTEGER,
        DOMAIN_NAME VARCHAR(255) NOT NULL,
        USER_NAME VARCHAR(45) NOT NULL,
	TIME_REGISTERED TIMESTAMP,
        KEY_HANDLE VARCHAR(200) NOT NULL,
        DEVICE_DATA LONGVARCHAR NOT NULL,
      	PRIMARY KEY (TENANT_ID, DOMAIN_NAME, USER_NAME, KEY_HANDLE));
