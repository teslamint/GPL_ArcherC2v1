/**
    Configuration of the HTTP Application gateway. See the configuration 
    sample file quicksec/samples/appgw_http.spd for usage examples. 

    <keywords Hypertext Transfer Protocol (HTTP), HTTP 
    (Hypertext Transfer Protocol), HTTP application gateway, ALG/HTTP>
 
    File: appgw_http.h
 
    @copyright
    Copyright (c) 2002 - 2007 SFNT Finland Oy, all rights reserved. 
 
 */

#ifndef SSH_APPGW_HTTP_H

#define SSH_APPGW_HTTP_H 1

/** The actions available to HTTP appgw rules. */

typedef enum {
  /** No action, denotes an unset value. */
  SSH_APPGW_HTTP_ACTION_NONE = 0,
  /** Allow the request. */
  SSH_APPGW_HTTP_ACTION_PASS = 1,
  /** Block the request with a pre-defined reply. */
  SSH_APPGW_HTTP_ACTION_BLOCK = 2,
  /** Cut the connection. */
  SSH_APPGW_HTTP_ACTION_CUT = 3
} SshAppgwHttpRuleAction;

/** Return values for functions manipulating an SshAppgwHttpConfig object. */
typedef enum {
  /** Bad operation, all parameters not defined. */
  SSH_APPGW_HTTP_CONFIG_BAD_OP = 0,
  /** Operation succesful. */
  SSH_APPGW_HTTP_CONFIG_OK = 1,
  /** A rule with the same name already exists. */
  SSH_APPGW_HTTP_CONFIG_RULE_EXISTS = 2,
  /** A block with the same name already exists. */
  SSH_APPGW_HTTP_CONFIG_BLOCK_EXISTS = 3,
  /** A clause with the same name already exists. */
  SSH_APPGW_HTTP_CONFIG_CLAUSE_EXISTS = 4,
  /** Out of memory. */
  SSH_APPGW_HTTP_CONFIG_OUT_OF_MEMORY = 5,
  /** Error parsing regex. */
  SSH_APPGW_HTTP_CONFIG_BAD_REGEX = 6,
  /** Could not find block. */
  SSH_APPGW_HTTP_CONFIG_COULD_NOT_FIND_BLOCK = 7,
  /** Could not find clause. */
  SSH_APPGW_HTTP_CONFIG_COULD_NOT_FIND_CLAUSE = 8
} SshAppgwHttpConfigValue;

/** Pointer to a block action struct. */
typedef struct SshAppgwHttpBlockActionRec *SshAppgwHttpBlockAction;
/** Pointer to a clause matching a header. */
typedef struct SshAppgwHttpMatchClauseRec *SshAppgwHttpMatchClause;
/** Rule for interpreting HTTP requests. */
typedef struct SshAppgwHttpRuleRec *SshAppgwHttpRule;
/** Configuration of the appgw HTTP. */
typedef struct SshAppgwHttpConfigRec *SshAppgwHttpConfig;

/** Create an empty configuration. 
   
    @return
    The function returns NULL if it runs out of memory. */
SshAppgwHttpConfig
ssh_appgw_http_create_config(void);

/** Destroys an SshAppgwHttpConfig object. */
void
ssh_appgw_http_destroy_config(SshAppgwHttpConfig config);

/** Set the TCP IP address and port that all TCP connections 
    should be redirected to. If the the_redirect() function 
    has not been called or the parameters are undefined,
    then the configuration specifies no TCP redirection. */
void
ssh_appgw_http_set_tcp_redirect(SshAppgwHttpConfig config,
                                const SshIpAddr tcp_dst,
                                SshUInt16 tcp_port);

/** Add a clause named clause_name, consisting of the
    "hdr_regex", "host" and "min_url_length" parameters.
    The "clause_name" and "config" parameters
    MUST be defined, the other parameters may be NULL or 0.

    A clause matches a request header if the URL in the HTTP 
    request-line is at least min_url_length bytes in length and the 
    destination host matches "host" or hdr_regex is a regex which 
    matches at least one line in the HTTP request header.

    The destination host used for the match is extracted from the 
    HTTP/1.1 Host: header line, or in the case of HTTP/1.0 or HTTP/0.9 
    from the requested URL. If it is not present in the requested URL 
    in this case, then the destination IP address is used as the 
    destination host. */

SshAppgwHttpConfigValue
ssh_appgw_http_add_clause(SshAppgwHttpConfig config,
                          const unsigned char *clause_name,
                          const unsigned char *hdr_regex,
                          const unsigned char *host,
                          int min_url_length);

/** Define a HTTP reply to be used in conjuction with
    a "block" action. The "config" and "block_name"
    parameters must be defined.

    @param http_code 
    Defines the return code to be used in the reply. The default 
    of 404 is used if http_code is less than 100 or greater than 999.

    @param content_type 
    Defines the content_type of the HTTP response. The default 
    is "text/html".

    @param data
    A pointer to a buffer which contains the body of the reply. 
    
    @param data_len
    Denotes the length (in bytes) of the buffer containing the body 
    of the reply. If data is NULL then a body consisting of one newline 
    character is used, if appropriate. */

SshAppgwHttpConfigValue
ssh_appgw_http_add_block(SshAppgwHttpConfig config,
                         const unsigned char *block_name,
                         int http_code,
                         const unsigned char *content_type,
                         const unsigned char *data,
                         int data_len);

/** An equivalent function to ssh_appgw_http_add_block() with two
    exceptions. 

   - A buffer 'header' of data to be inserted into the HTTP
     reply can be be provided as input. This buffer can
     be freed after the call returns.  This buffer
     can be NULL.

   - If content_type == NULL, then no default is set.
     If the header buffer does not provide a content-type
     then no content-type is set in the reply. */

SshAppgwHttpConfigValue
ssh_appgw_http_add_block_custom_header(SshAppgwHttpConfig config,
                                       const unsigned char *block_name,
                                       int http_code,
                                       const unsigned char *content_type,
                                       const unsigned char *header,
                                       int header_len,
                                       const unsigned char *data,
                                       int data_len);

/** Define a rule for handling HTTP requests. The "config" and 
    "rule_name" parameters must be defined. 
    
    The order of the rules denotes the precedence of the rules. 
    The higher the precedence of a rule is, the earlier it will be 
    considered. A request can only match one rule. 

    The function places a handle to a SshAppgwHttpRule object in 
    *rule, which can be used by ssh_appgw_http_rule_set_action() or 
    ssh_appgw_http_rule_add_clause(). 
    
    @param action
    Denotes the action to be taken if the rule is triggered. 
    
    @param block_name
    Denotes the name of a HTTP reply previously defined using
    ssh_appgw_http_add_block() if the action is
    set to SSH_APPGW_HTTP_ACTION_BLOCK.

    */

SshAppgwHttpConfigValue
ssh_appgw_http_add_rule(SshAppgwHttpConfig config,
                        const unsigned char *rule_name,
                        int precedence,
                        SshAppgwHttpRuleAction action,
                        const unsigned char *block_name,
                        SshAppgwHttpRule *rule);

/** Set the action performed if a rule is triggered. If
    the action is SSH_APPGW_HTTP_ACTION_BLOCK, then 'param' 
    must be a pointer to a string which is the name
    of a previously defined block. */
SshAppgwHttpConfigValue
ssh_appgw_http_rule_set_action(SshAppgwHttpConfig config,
                               SshAppgwHttpRule r,
                               SshAppgwHttpRuleAction action,
                               const char *param);

/** Add a clause which must be matched for a rule to be triggered
    by a request. */
SshAppgwHttpConfigValue
ssh_appgw_http_rule_add_clause(SshAppgwHttpConfig config,
                               SshAppgwHttpRule rule,
                               const unsigned char *clause_name);

/** Marshal a configuration into a platform-independent
    representation that can be transferred. 
    
    The HTTP Appgw expects a data blob produced by 
    ssh_appgw_http_marshal_config to be provided to it via 
    ssh_pm_service_set_appgw_config().

    The recipient is expected to ssh_free() the returned buffer after 
    it has been provided to ssh_pm_service_set_appgw_config(). 
    
    @return
    Returns a pointer to a buffer containing the marshaled 
    representation and places the length of this buffer in *res_len. 
    The function returns NULL if it runs out of memory.

    */

unsigned char*
ssh_appgw_http_marshal_config(SshAppgwHttpConfig config,
                              size_t *res_len);

/** Unmarshal a configuration back into a SshAppgwHttpConfig
    object. 
    
    @return
    The function returns NULL if it runs out of memory. 
    
    */

SshAppgwHttpConfig
ssh_appgw_http_unmarshal_config(const unsigned char *data,
                                size_t len);


#endif /* SSH_APPGW_HTTP_H */
