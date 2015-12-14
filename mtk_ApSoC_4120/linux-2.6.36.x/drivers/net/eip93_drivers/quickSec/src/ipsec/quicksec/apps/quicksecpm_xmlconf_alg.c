/*
 * quicksecpm_xmlconf_alg.c
 *
 * Copyright:
 *       Copyright (c) 2002, 2003, 2004, 2005 SFNT Finland Oy.
 *       All rights reserved.
 *
 * Application gateway configuration parsing from XML files.
 */

#include "sshincludes.h"
#include "quicksecpm_xmlconf_i.h"
#include "appgw_dns.h"
#include "appgw_http.h"
#include "appgw_sip.h"

#ifdef SSHDIST_AV
#ifdef WITH_AV_ALG
#include "appgw_av.h"
#endif /* WITH_AV_ALG */
#endif /* SSHDIST_AV */

#ifdef SSHDIST_IPSEC_NAT
#ifdef SSHDIST_IPSEC_FIREWALL

/************************** Types and definitions ***************************/

#define SSH_DEBUG_MODULE "SshIpsecPmXmlConfAlg"

/************************** Static help functions ***************************/

/* Return the contents of the first PCDATA child of the XML node
   `node'.  The function returns NULL if the node `node' does not have
   such children. */
static const unsigned char *
ssh_xml_node_get_first_child_pcdata(SshXmlDomNode node, size_t *len_return)
{
  SshXmlDomNode n;

  for (n = ssh_xml_dom_node_get_first_child(node);
       n;
       n = ssh_xml_dom_node_get_next(n))
    if (ssh_xml_dom_node_get_type(n) == SSH_XML_DOM_NODE_TEXT)
      return ssh_xml_dom_node_get_value(n, len_return);

  return NULL;
}


/*************************** Pass-through TCP ALG ***************************/

Boolean
ssh_ipm_appgw_pass_through_tcp_config(SshIpmContext ctx, SshXmlDom dom,
                                      unsigned char **config_return,
                                      size_t *config_len_return)
{
  SshAppgwPassThroughTcpConfig config;
  SshXmlDomNode root;
  const unsigned char *ucp;
  size_t len;
  SshADTContainer attributes;

  /* Create a config object. */
  config = ssh_appgw_pass_through_tcp_config_create();
  if (config == NULL)
    {
      ssh_ipm_error(ctx,
                    "Could not create Pass-through TCP ALG "
                    "configuration data");
      goto error;
    }

  /* Lookup the configuration data element. */
  root = ssh_xml_dom_get_root_node(dom);
  for (root = ssh_xml_dom_node_get_first_child(root);
       root;
       root = ssh_xml_dom_node_get_next(root))
    {
      const unsigned char *redirect_ip;
      const unsigned char *redirect_port;

      if (ssh_xml_dom_node_get_type(root) != SSH_XML_DOM_NODE_ELEMENT)
        continue;

      /* Check the node name. */
      ucp = ssh_xml_dom_node_get_name(root, &len);
      if (!ssh_xml_match(ucp, len, ssh_custr("alg-pass-through-tcp"), 0))
        {
          ssh_ipm_error(ctx,
                        "Invalid element `%s' for Pass-through TCP ALG config",
                        ucp);
          goto error;
        }
      /* Get attributes. */
      attributes = ssh_xml_dom_node_get_attributes(root);

      /* Fetch attributes. */
      redirect_ip = ssh_xml_get_attr_value(attributes,
                                           ssh_custr("redirect-ip"), 0, NULL);
      redirect_port = ssh_xml_get_attr_value(attributes,
                                             ssh_custr("redirect-port"), 0,
                                             NULL);

      if (!ssh_appgw_pass_through_tcp_config_redirect(config, redirect_ip,
                                                      redirect_port))
        {
          ssh_ipm_error(ctx, "Could not configure redirection");
          goto error;
        }
    }

  /* Marshal configuration data. */
  *config_return
    = ssh_appgw_pass_through_tcp_config_marshal(config, config_len_return);
  if (*config_return == NULL)
    {
      ssh_ipm_error(ctx,
                    "Could not allocate Pass-through TCP ALG "
                    "configuration data");
      goto error;
    }

  /* We are done with the config object. */
  ssh_appgw_pass_through_tcp_config_destroy(config);

  /* All done. */
  return TRUE;


  /* Error handling. */

 error:

  ssh_appgw_pass_through_tcp_config_destroy(config);

  return FALSE;
}


/********************************* FTP ALG **********************************/

Boolean
ssh_ipm_appgw_ftp_config(SshIpmContext ctx, SshXmlDom dom,
                         unsigned char **config_return,
                         size_t *config_len_return)
{
  SshAppgwFtpConfig config;
  SshXmlDomNode root, node;
  const unsigned char *ucp;
  size_t len;
  SshADTContainer attributes;
  SshXmlAttrEnumCtxStruct attr_enum;
  const unsigned char *value;
  size_t value_len;
  SshUInt32 flags = 0;

  /* Create a config object. */
  config = ssh_appgw_ftp_config_create();
  if (config == NULL)
    {
      ssh_ipm_error(ctx, "Could not create FTP ALG configuration data");
      goto error;
    }

  /* Lookup the configuration data element. */
  root = ssh_xml_dom_get_root_node(dom);
  for (root = ssh_xml_dom_node_get_first_child(root);
       root;
       root = ssh_xml_dom_node_get_next(root))
    {
      if (ssh_xml_dom_node_get_type(root) != SSH_XML_DOM_NODE_ELEMENT)
        continue;

      /* Check the node name. */
      ucp = ssh_xml_dom_node_get_name(root, &len);
      if (!ssh_xml_match(ucp, len, ssh_custr("alg-ftp"), 0))
        {
          ssh_ipm_error(ctx, "Invalid element `%s' for FTP ALG config", ucp);
          goto error;
        }
      /* Get attributes. */
      attributes = ssh_xml_dom_node_get_attributes(root);

      /* Process attributes. */
      ssh_xml_attr_value_enum_init(attributes, ssh_custr("flags"), 0,
                                   SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);
      while ((value = ssh_xml_attr_value_enum_next(&attr_enum, &value_len))
             != NULL)
        {
          if (ssh_xml_match(value, value_len,
                            ssh_custr("client-can-change-ip"), 0))
            flags |= SSH_APPGW_FTP_CLIENT_CAN_CHANGE_IP;
          else if (ssh_xml_match(value, value_len,
                                 ssh_custr("server-can-change-ip"), 0))
            flags |= SSH_APPGW_FTP_SERVER_CAN_CHANGE_IP;
          else
            {
              ssh_ipm_error(ctx, "Unknown flag `%.*s'",
                            value_len, value);
              goto error;
            }
        }
      ssh_appgw_ftp_config_set_flags(config, flags);

      /* Process all children of the configuration element. */
      for (node = ssh_xml_dom_node_get_first_child(root);
           node;
           node = ssh_xml_dom_node_get_next(node))
        {
          /* We are only interested in elements. */
          if (ssh_xml_dom_node_get_type(node) != SSH_XML_DOM_NODE_ELEMENT)
            continue;

          /* Process this element. */
          ucp = ssh_xml_dom_node_get_name(node, &len);
          if (ssh_xml_match(ucp, len, ssh_custr("disable"), 0))
            {
              /* Get the command name. */
              ucp = ssh_xml_node_get_first_child_pcdata(node, &len);
              if (ucp == NULL)
                {
                  ssh_ipm_error(ctx,
                                "No FTP command name specified for `disable'");
                  goto error;
                }
              if (!ssh_appgw_ftp_config_disable_cmd(config, (char *) ucp))
                {
                  ssh_ipm_error(ctx, "Unknown FTP command `%s'", ucp);
                  goto error;
                }
            }
          else if (ssh_xml_match(ucp, len, ssh_custr("content-filter"), 0))
            {
              SshAppgwFtpContentFilterType type;

              /* Get the content filter name. */
              ucp = ssh_xml_node_get_first_child_pcdata(node, &len);
              if (ucp == NULL)
                {
                  ssh_ipm_error(ctx,
                                "No content filter name specified for "
                                "`content-filter'");
                  goto error;
                }
              if (ssh_xml_match(ucp, len, ssh_custr("none"), 0))
                type = SSH_APPGW_FTP_CONTENT_FILTER_NONE;
              else if (ssh_xml_match(ucp, len, ssh_custr("simple"), 0))
                type = SSH_APPGW_FTP_CONTENT_FILTER_SIMPLE;
              else if (ssh_xml_match(ucp, len, ssh_custr("MD5"), 0))
                type = SSH_APPGW_FTP_CONTENT_FILTER_MD5;
              else
                {
                  ssh_ipm_error(ctx, "Unknown content filter `%s'", ucp);
                  goto error;
                }

              ssh_appgw_ftp_config_content_filter(config, type);
            }

          /* Else ignore unknown elements. */
        }
    }

  /* Marshal configuration data. */
  *config_return = ssh_appgw_ftp_config_marshal(config, config_len_return);
  if (*config_return == NULL)
    {
      ssh_ipm_error(ctx, "Could not allocate FTP ALG configuration data");
      goto error;
    }

  /* We are done with the config object. */
  ssh_appgw_ftp_config_destroy(config);

  /* All done. */
  return TRUE;


  /* Error handling. */

 error:

  ssh_appgw_ftp_config_destroy(config);

  return FALSE;
}


/********************************* HTTP ALG *********************************/

Boolean
ssh_ipm_appgw_http_config(SshIpmContext ctx, SshXmlDom dom,
                          unsigned char **config_return,
                          size_t *config_len_return)
{
  SshAppgwHttpConfig config;
  SshXmlDomNode node, root;
  const unsigned char *ucp;
  SshADTContainer attributes;
  size_t len;

  config = ssh_appgw_http_create_config();

  if (config == NULL)
    {
      ssh_ipm_error(ctx, "Could not create HTTP ALG configuration data");
      return FALSE;
    }

  root = ssh_xml_dom_get_root_node(dom);

  /* Traverse through all HTTP ALG config elements */
  for (root = ssh_xml_dom_node_get_first_child(root);
       root;
       root = ssh_xml_dom_node_get_next(root))
    {
      const unsigned char *def_precedence_str, *redirect_dst;
      const char *redirect_port_str;
      int rule_default_precedence = 10000000;

      if (ssh_xml_dom_node_get_type(root) != SSH_XML_DOM_NODE_ELEMENT)
        continue;

      /* Check the node name. */
      ucp = ssh_xml_dom_node_get_name(root, &len);

      if (!ssh_xml_match(ucp, len, ssh_custr("alg-http"), 0))
        {
          ssh_ipm_error(ctx, "Invalid element `%s' for HTTP ALG config",
                        ucp);
          goto error;
        }

      /* Grab attributes */
      attributes = ssh_xml_dom_node_get_attributes(root);

      redirect_dst = ssh_xml_get_attr_value(attributes,
                                            ssh_custr("redirect-ip"), 0, NULL);
      redirect_port_str =
        (char *)ssh_xml_get_attr_value(attributes,
                                       ssh_custr("redirect-port"), 0, NULL);
      def_precedence_str = ssh_xml_get_attr_value(attributes,
                                                  ssh_custr("precedence"), 0,
                                                  NULL);

      if (redirect_dst && redirect_port_str)
        {
          SshIpAddrStruct tcp_dst;
          int tcp_port;

          if (ssh_ipaddr_parse(&tcp_dst, redirect_dst) == FALSE)
            {
              ssh_ipm_error(ctx, "Error parsing IP address '%s'.",
                            redirect_dst);
              goto error;
            }

          tcp_port = strtoul(redirect_port_str, NULL, 0);

          ssh_appgw_http_set_tcp_redirect(config, &tcp_dst,
                                          (SshUInt16)tcp_port);
        }

      if (def_precedence_str)
        rule_default_precedence = ssh_ustrtoul(def_precedence_str, NULL,
                                          0);

      /* Process all children of the configuration element. */
      for (node = ssh_xml_dom_node_get_first_child(root);
           node;
           node = ssh_xml_dom_node_get_next(node))
        {
          /* Only elements are relevant here. */
          if (ssh_xml_dom_node_get_type(node) != SSH_XML_DOM_NODE_ELEMENT)
            continue;

          /* Grab attributes */
          attributes = ssh_xml_dom_node_get_attributes(node);

          /* Check the node name. */
          ucp = ssh_xml_dom_node_get_name(node, &len);

          /* Handle clause element */
          if (ssh_xml_match(ucp, len, ssh_custr("clause"), 0))
            {
              const unsigned char *name, *regex, *host, *min_url_lenstr;
              unsigned int min_url_len;

              /* Grab attribute values */
              name = ssh_xml_get_attr_value(attributes, ssh_custr("name"), 0,
                                            NULL);
              regex = ssh_xml_get_attr_value(attributes, ssh_custr("regex"), 0,
                                             NULL);
              host = ssh_xml_get_attr_value(attributes, ssh_custr("host"), 0,
                                            NULL);
              min_url_lenstr =
                ssh_xml_get_attr_value(attributes,
                                       ssh_custr("min-url-length"), 0, NULL);
              min_url_len = 0;
              if (min_url_lenstr != NULL)
                min_url_len = ssh_ustrtoul(min_url_lenstr, NULL, 0);

              /* Create clause in config */
              if (name == NULL)
                {
                  ssh_ipm_error(ctx, "No name for clause specified.");
                  goto error;
                }

              if (ssh_appgw_http_add_clause(config, name, regex, host,
                                            min_url_len)
                  != SSH_APPGW_HTTP_CONFIG_OK)
                {
                  ssh_ipm_error(ctx,
                                "Could not add clause to HTTP ALG config");
                  goto error;
                }
            }
          else if (ssh_xml_match(ucp, len, ssh_custr("page"), 0))
            {
              const unsigned char *name, *type, *code_str;
              const unsigned char *body, *header;
              unsigned int code;

              /* Grab relevant attribute values */
              name = ssh_xml_get_attr_value(attributes, ssh_custr("name"), 0,
                                            NULL);
              type = ssh_xml_get_attr_value(attributes, ssh_custr("type"), 0,
                                            NULL);
              code_str = ssh_xml_get_attr_value(attributes, ssh_custr("code"),
                                                0, NULL);
              body = ssh_xml_get_attr_value(attributes, ssh_custr("body"), 0,
                                            NULL);
              header = ssh_xml_get_attr_value(attributes, ssh_custr("header"),
                                              0, NULL);
              code = 200;
              if (code_str == NULL)
                code = ssh_ustrtoul(code_str, NULL, 0) % 1000;

              if (type == NULL && header == NULL)
                type = ssh_custr("text/html");

              if (name == NULL)
                {
                  ssh_ipm_error(ctx, "No name for page specified.");
                  goto error;
                }

              if (ssh_appgw_http_add_block_custom_header(config, name, code,
                                                         type, header,
                                                         header ?
                                                 ssh_ustrlen(header) : 0,
                                                         body,
                                                         body ?
                                                   ssh_ustrlen(body) : 0)
                  != SSH_APPGW_HTTP_CONFIG_OK)
                {
                  ssh_ipm_error(ctx,
                                "Error adding HTTP page to HTTP ALG "
                                "configuration.");
                  goto error;
                }
            }
          else if (ssh_xml_match(ucp, len, ssh_custr("rule"), 0))
            {
              const unsigned char *action, *enum_str;
              const unsigned char *precedence_str, *name, *page;
              size_t enum_str_len;
              int precedence;
              SshAppgwHttpRuleAction act;
              SshXmlAttrEnumCtxStruct enum_ctx;
              SshAppgwHttpRule rule;

              /* Grab relevant attribute values */
              name = ssh_xml_get_attr_value(attributes, ssh_custr("name"), 0,
                                            NULL);
              action = ssh_xml_get_attr_value(attributes,
                                              ssh_custr("action"), 0, NULL);
              page = ssh_xml_get_attr_value(attributes, ssh_custr("page"), 0,
                                            NULL);
              precedence_str = ssh_xml_get_attr_value(attributes,
                                                      ssh_custr("precedence"),
                                                      0, NULL);
              if (name == NULL)
                {
                  ssh_ipm_error(ctx, "No name for rule specified.");
                  goto error;
                }

              /* Parse the attribute values into something sane. */
              act = SSH_APPGW_HTTP_ACTION_PASS;
              if (action)
                {
                  if (strcmp((char *)action, "pass") == 0)
                    act = SSH_APPGW_HTTP_ACTION_PASS;
                  else if (strcmp((char *)action, "block") == 0)
                    act = SSH_APPGW_HTTP_ACTION_BLOCK;
                  else if (strcmp((char *)action, "cut") == 0)
                    act = SSH_APPGW_HTTP_ACTION_CUT;
                  else
                    {
                      ssh_ipm_error(ctx,
                                    "Unregonized HTTP ALG rule action '%s'",
                                    (char *)action);
                      goto error;
                    }

                }

              if (precedence_str)
                precedence = ssh_ustrtoul(precedence_str, NULL, 0);
              else
                precedence = rule_default_precedence--;

              /* Actually add the rule to the configuration without
                 any clauses. */
              if (ssh_appgw_http_add_rule(config, name, precedence, act,
                                          page, &rule)
                  != SSH_APPGW_HTTP_CONFIG_OK)
                {
                  ssh_ipm_error(ctx,
                                "Error adding rule to HTTP ALG "
                                "configuration.");
                  goto error;
                }

              /* Enumerate through the clauses attribute */
              ssh_xml_attr_value_enum_init(attributes,
                                           (unsigned char *)"clauses",
                                           strlen("clauses"),
                                           SSH_XML_ATTR_ENUM_NMTOKENS,
                                           &enum_ctx);

              while((enum_str = ssh_xml_attr_value_enum_next(&enum_ctx,
                                                             &enum_str_len))
                    != NULL)
                {
                  if (ssh_appgw_http_rule_add_clause(config, rule, enum_str)
                      != SSH_APPGW_HTTP_CONFIG_OK)
                    {
                      ssh_ipm_error(ctx,
                                    "Error adding clause '%s' to rule '%s' of "
                                    "HTTP ALG",
				    enum_str, name);
                      goto error;
                    }
                }


            }
          else
            {
              ssh_ipm_error(ctx, "Invalid element '%s' for HTTP ALG config",
                            ucp);
              goto error;
            }
        }
    }


  /* Marshal configuration data. */
  *config_return = ssh_appgw_http_marshal_config(config, config_len_return);
  if (*config_return == NULL)
    goto error;

  /* We are done with the config object. */
  ssh_appgw_http_destroy_config(config);
  return TRUE;

 error:
  ssh_appgw_http_destroy_config(config);
  return FALSE;
}

/******************************* Socksify ALG *******************************/

Boolean
ssh_ipm_appgw_socksify_config(SshIpmContext ctx, SshXmlDom dom,
                              unsigned char **config_return,
                              size_t *config_len_return)
{
  SshAppgwSocksifyConfig config;
  SshXmlDomNode root, node;
  const unsigned char *ucp;
  size_t len;
  SshADTContainer attributes;

  /* Create a config object. */
  config = ssh_appgw_socksify_config_create();
  if (config == NULL)
    {
      ssh_ipm_error(ctx, "Could not create SOCKSIFY ALG configuration data");
      goto error;
    }

  /* Lookup the configuration data element. */
  root = ssh_xml_dom_get_root_node(dom);
  for (root = ssh_xml_dom_node_get_first_child(root);
       root;
       root = ssh_xml_dom_node_get_next(root))
    {
      if (ssh_xml_dom_node_get_type(root) != SSH_XML_DOM_NODE_ELEMENT)
        continue;

      /* Check the node name. */
      ucp = ssh_xml_dom_node_get_name(root, &len);
      if (!ssh_xml_match(ucp, len, ssh_custr("alg-socksify"), 0))
        {
          ssh_ipm_error(ctx, "Invalid element `%s' for SOCKSIFY ALG config",
                        ucp);
          goto error;
        }

      /* Process all children of the configuration element. */
      for (node = ssh_xml_dom_node_get_first_child(root);
           node;
           node = ssh_xml_dom_node_get_next(node))
        {
          /* We are only interested in elements. */
          if (ssh_xml_dom_node_get_type(node) != SSH_XML_DOM_NODE_ELEMENT)
            continue;

          /* Get attributes. */
          attributes = ssh_xml_dom_node_get_attributes(node);

          /* Process this element. */
          ucp = ssh_xml_dom_node_get_name(node, &len);
          if (ssh_xml_match(ucp, len, ssh_custr("server"), 0))
            {
              const unsigned char *addr;
              const unsigned char *port;
              const unsigned char *version;
              const unsigned char *user_name;
              size_t user_name_len;
              const unsigned char *password;
              size_t password_len;

              /* Fetch attributes. */
              addr = ssh_xml_get_attr_value(attributes, ssh_custr("address"),
                                            0, NULL);
              if (addr == NULL)
                {
                  ssh_ipm_error(ctx, "No server address specified");
                  goto error;
                }
              port = ssh_xml_get_attr_value(attributes, ssh_custr("port"), 0,
                                            NULL);
              if (port == NULL)
                port = ssh_custr("1080");

              version = ssh_xml_get_attr_value(attributes,
                                               ssh_custr("version"), 0, NULL);
              if (version == NULL)
                version = ssh_custr("4");

              user_name = ssh_xml_get_attr_value(attributes,
                                                 ssh_custr("user-name"), 0,
                                                 &user_name_len);
              password = ssh_xml_get_attr_value(attributes,
                                                 ssh_custr("password"), 0,
                                                 &password_len);

              if (!ssh_appgw_socksify_config_server(config, addr, port,
                                                    version,
                                                    user_name, user_name_len,
                                                    password, password_len))
                {
                  ssh_ipm_error(ctx, "Could not configure SOCKS server");
                  goto error;
                }
            }
          else if (ssh_xml_match(ucp, len, ssh_custr("connect"), 0))
            {
              const unsigned char *addr;
              const unsigned char *port;

              /* Fetch attributes. */
              addr = ssh_xml_get_attr_value(attributes, ssh_custr("address"),
                                            0, NULL);
              if (addr == NULL)
                {
                  ssh_ipm_error(ctx, "No connect IP address specified");
                  goto error;
                }
              port = ssh_xml_get_attr_value(attributes, ssh_custr("port"), 0,
                                            NULL);

              if (!ssh_appgw_socksify_config_destination(config, addr, port))
                {
                  ssh_ipm_error(ctx, "Could not configure destination");
                  goto error;
                }
            }
          /* Else ignore unknown elements. */
        }
    }

  /* Marshal configuration data. */
  *config_return = ssh_appgw_socksify_config_marshal(config,
                                                     config_len_return);
  if (*config_return == NULL)
    {
      ssh_ipm_error(ctx, "Could not allocate SOCKSIFY ALG configuration data");
      goto error;
    }

  /* We are done with the config object. */
  ssh_appgw_socksify_config_destroy(config);

  /* All done. */
  return TRUE;


  /* Error handling. */

 error:

  ssh_appgw_socksify_config_destroy(config);

  return FALSE;
}

/********************************* SIP ALG **********************************/
Boolean
ssh_ipm_appgw_sip_config(SshIpmContext ctx, SshXmlDom dom,
                         unsigned char **config_return,
                         size_t *config_len_return)
{
  SshAppgwSipConfig config;
  SshXmlDomNode root, node;
  const unsigned char *ucp;
  size_t len;

  /* Create a config object. */
  config = ssh_appgw_sip_config_create();
  if (config == NULL)
    goto error;

  root = ssh_xml_dom_get_root_node(dom);
  for (root = ssh_xml_dom_node_get_first_child(root);
       root;
       root = ssh_xml_dom_node_get_next(root))
    {
      if (ssh_xml_dom_node_get_type(root) != SSH_XML_DOM_NODE_ELEMENT)
        continue;

      ucp = ssh_xml_dom_node_get_name(root, &len);
      if (!ssh_xml_match(ucp, len, ssh_custr("alg-sip"), 0))
        {
          ssh_ipm_error(ctx, "Invalid element `%s' for SIP ALG config", ucp);
          goto error;
        }

      /* Process children for this configuration element. */
      for (node = ssh_xml_dom_node_get_first_child(root);
           node;
           node = ssh_xml_dom_node_get_next(node))
        {

          if (ssh_xml_dom_node_get_type(node) != SSH_XML_DOM_NODE_ELEMENT)
            continue;
          ucp = ssh_xml_dom_node_get_name(node, &len);

          if (ssh_xml_match(ucp, len, ssh_custr("internal-network"), 0))
            {
              SshIpAddrStruct intnet;
              SshXmlDomNode netdef;

              netdef = node;

              SSH_IP_UNDEFINE(&intnet);
              ucp = ssh_xml_node_get_first_child_pcdata(netdef, &len);
              if (ucp == NULL
                  || !ssh_ipaddr_parse_with_mask(&intnet, ucp, NULL)
                  || !(SSH_IP_IS4(&intnet) || SSH_IP_IS6(&intnet)))
                {
                  ssh_ipm_error(ctx,
                                "internal-network is not valid IPv4 or "
                                "IPv6 subnet.");
                  goto error;
                }
              ssh_appgw_sip_add_internal_network(config, &intnet);
            }

          if (ssh_xml_match(ucp, len, ssh_custr("conduit"), 0))
            {
              SshIpAddrStruct intip, extip;
              SshXmlDomNode conduit, c_node;
              SshUInt32 intport = 5060, extport = 5060;

              conduit = node;

              SSH_IP_UNDEFINE(&intip);
              SSH_IP_UNDEFINE(&extip);

              for (c_node = ssh_xml_dom_node_get_first_child(conduit);
                   c_node;
                   c_node = ssh_xml_dom_node_get_next(c_node))
                {
                  if (ssh_xml_dom_node_get_type(c_node) !=
                      SSH_XML_DOM_NODE_ELEMENT)
                    continue;

                  ucp = ssh_xml_dom_node_get_name(c_node, &len);
                  if (ssh_xml_match(ucp, len,
                                    ssh_custr("internal-ip"), 0))
                    {
                      ucp = ssh_xml_node_get_first_child_pcdata(c_node, &len);
                      if (ucp == NULL
                          || !ssh_ipaddr_parse(&intip, ucp)
                          || !(SSH_IP_IS4(&intip) || SSH_IP_IS6(&intip)))
                        {
                          ssh_ipm_error(ctx,
                                        "internal-ip is not valid "
                                        "IPv4 or IPv6 address.");
                          goto error;
                        }
                    }
                  else if (ssh_xml_match(ucp, len,
                                         ssh_custr("internal-port"), 0))
                    {
                      ucp = ssh_xml_node_get_first_child_pcdata(c_node, &len);
                      if (ucp != NULL)
                        {
                          errno = 0;
                          intport = strtoul(ucp, NULL, 0);
                          if (errno != 0 ||
                              intport == 0 || intport > 65535)
                            {
                              ssh_ipm_error(ctx,
                                            "internal-port is invalid.");
                              goto error;
                            }
                        }
                      else
                        {
                          ssh_ipm_error(ctx,
                                        "internal-port pcdata is empty");
                          goto error;
                        }

                    }
                  else if (ssh_xml_match(ucp, len,
                                         ssh_custr("external-ip"), 0))
                    {
                      ucp = ssh_xml_node_get_first_child_pcdata(c_node, &len);
                      if (ucp == NULL
                          || !ssh_ipaddr_parse(&extip, ucp)
                          || !(SSH_IP_IS4(&extip) || SSH_IP_IS6(&extip)))
                        {
                          ssh_ipm_error(ctx,
                                        "external-ip is not valid "
                                        "IPv4 or IPv6 address.");
                          goto error;
                        }
                    }
                  else if (ssh_xml_match(ucp, len,
                                         ssh_custr("external-port"), 0))
                    {
                      ucp = ssh_xml_node_get_first_child_pcdata(c_node, &len);
                      if (ucp != NULL)
                        {
                          errno = 0;
                          extport = strtoul(ucp, NULL, 0);
                          if (errno != 0 ||
                              extport == 0 || extport > 65535)
                            {
                              ssh_ipm_error(ctx,
                                            "external-port is invalid.");
                              goto error;
                            }
                        }
                      else
                        {
                          ssh_ipm_error(ctx,
                                        "external-port pcdata is empty");
                          goto error;
                        }
                    }
                }

              if ((SSH_IP_IS4(&intip) && !SSH_IP_IS4(&extip)) ||
                  (SSH_IP_IS6(&intip) && !SSH_IP_IS6(&extip)))
                {
                  ssh_ipm_error(ctx,
                                "internal-ip and external-ip are not "
                                "of the same address family.");
                  goto error;
                }

              ssh_appgw_sip_add_conduit(config,
                                        &extip, (SshUInt16)extport,
                                        &intip, (SshUInt16)intport);
            }
        }
    }

  /* Marshal configuration data. */
  *config_return = ssh_appgw_sip_marshal_config(config, config_len_return);
  if (*config_return == NULL)
    goto error;

  /* We are done with the config object. */
  ssh_appgw_sip_destroy_config(config);

  /* All done. */
  return TRUE;

  /* Error handling. */
 error:
  ssh_appgw_sip_destroy_config(config);
  return FALSE;
}

/********************************* DNS ALG **********************************/

Boolean
ssh_ipm_appgw_dns_config(SshIpmContext ctx, SshXmlDom dom,
                         unsigned char **config_return,
                         size_t *config_len_return)
{
  SshAppgwDNSConfig config;
  SshXmlDomNode root, node, mapping;
  const unsigned char *ucp;
  SshADTContainer attributes;
  SshXmlAttrEnumCtxStruct attr_enum;
  const unsigned char *value;
  size_t value_len, len;

  /* Create a config object. */
  config = ssh_appgw_dns_config_create();
  if (config == NULL)
    goto error;

  root = ssh_xml_dom_get_root_node(dom);
  for (root = ssh_xml_dom_node_get_first_child(root);
       root;
       root = ssh_xml_dom_node_get_next(root))
    {
      if (ssh_xml_dom_node_get_type(root) != SSH_XML_DOM_NODE_ELEMENT)
        continue;

      ucp = ssh_xml_dom_node_get_name(root, &len);
      if (!ssh_xml_match(ucp, len, ssh_custr("alg-dns"), 0))
        {
          ssh_ipm_error(ctx, "Invalid element `%s' for DNS ALG config", ucp);
          goto error;
        }

      /* Get and process attributes. Currently none, but have this small code
         here for the future. */
      attributes = ssh_xml_dom_node_get_attributes(root);
      ssh_xml_attr_value_enum_init(attributes, ssh_custr("flags"), 0,
                                   SSH_XML_ATTR_ENUM_NMTOKENS, &attr_enum);
      while ((value =
              ssh_xml_attr_value_enum_next(&attr_enum, &value_len)) != NULL)
        {
          ;
        }

      /* Process children for this configuration element. */
      for (mapping = ssh_xml_dom_node_get_first_child(root);
           mapping;
           mapping = ssh_xml_dom_node_get_next(mapping))
        {

          if (ssh_xml_dom_node_get_type(mapping) != SSH_XML_DOM_NODE_ELEMENT)
            continue;
          ucp = ssh_xml_dom_node_get_name(mapping, &len);

          if (ssh_xml_match(ucp, len, ssh_custr("mapping"), 0))
            {
              SshIpAddrStruct intip, extip;

              SSH_IP_UNDEFINE(&intip);
              SSH_IP_UNDEFINE(&extip);

              for (node = ssh_xml_dom_node_get_first_child(mapping);
                   node;
                   node = ssh_xml_dom_node_get_next(node))
                {
                  if (ssh_xml_dom_node_get_type(node) !=
                      SSH_XML_DOM_NODE_ELEMENT)
                    continue;

                  ucp = ssh_xml_dom_node_get_name(node, &len);
                  if (ssh_xml_match(ucp, len, ssh_custr("internal-ip"), 0))
                    {
                      ucp = ssh_xml_node_get_first_child_pcdata(node, &len);
                      if (!ucp ||
			  !ssh_ipaddr_parse(&intip, ucp))
                        {
                          ssh_ipm_error(ctx,
                                        "internal-ip is not valid "
                                        "IPv4 or IPv6 address.");
                          goto error;
                        }
                    }
                  if (ssh_xml_match(ucp, len, ssh_custr("external-ip"), 0))
                    {
                      ucp = ssh_xml_node_get_first_child_pcdata(node, &len);
                      if (!ucp ||
			  !ssh_ipaddr_parse(&extip, ucp))
                        {
                          ssh_ipm_error(ctx,
                                        "external-ip is not valid "
                                        "IPv4 or IPv6 address.");
                          goto error;
                        }
                    }
                }
              if (!SSH_IP_DEFINED(&intip) || !SSH_IP_DEFINED(&extip))
		{
		  ssh_ipm_error(ctx,
				"Mapping needs to define both "
				"internal-ip and external-ip.");
		  goto error;
		}
	      if ((SSH_IP_IS4(&intip) && !SSH_IP_IS4(&extip)) ||
		  (SSH_IP_IS6(&intip) && !SSH_IP_IS6(&extip)))
		{
		  ssh_ipm_error(ctx,
				"Mapping defines "
				"internal-ip and external-ip, but they are not "
				"of the same address family.");
		  goto error;
		}
	      ssh_appgw_dns_static_nat_map(config, &extip, &intip);
            }
        }
    }

  /* Marshal configuration data. */
  *config_return = ssh_appgw_dns_marshal_config(config, config_len_return);
  if (*config_return == NULL)
    goto error;

  /* We are done with the config object. */
  ssh_appgw_dns_destroy_config(config);

  /* All done. */
  return TRUE;

  /* Error handling. */
 error:
  ssh_ipm_error(ctx, "Could not create DNS ALG configuration data");
  ssh_appgw_dns_destroy_config(config);

  return FALSE;
}

#endif /* SSHDIST_IPSEC_FIREWALL */
#endif /* SSHDIST_IPSEC_NAT */

#ifdef SSHDIST_AV
#ifdef WITH_AV_ALG
/*************************** Anti-Virus SMTP ALG ***************************/

Boolean
ssh_ipm_appgw_av_config(SshIpmContext ctx, SshXmlDom dom,
                        unsigned char **config_return,
                        size_t *config_len_return)
{
  SshAppgwAvConfig config;
  SshXmlDomNode root;
  const unsigned char *ucp;
  size_t len;
  SshADTContainer attributes;
  int i;
  int attr_count;
  const unsigned char *attr_names[SSH_APPGW_AV_NUM_PARAMS] = {
    "redirect-port", "max-connections", "max-content-size", "timeout",
    "av-engines", "redirect-ip", "working-directory", "engine-address",
    "ok-action", "virus-action", "warning-action", "suspect-action",
    "protected-action", "corrupt-action", "error-action", "partial-action"
  };
  const unsigned char *(param_tbl[SSH_APPGW_AV_NUM_PARAMS]);

  memset(param_tbl, 0, sizeof(param_tbl));

  /* Create a config object. */
  config = ssh_appgw_av_config_create();
  if (config == NULL)
    {
      ssh_ipm_error(ctx, "Could not create AV ALG configuration data");
      goto error;
    }

  /* Lookup the configuration data element. */
  root = ssh_xml_dom_get_root_node(dom);
  for (root = ssh_xml_dom_node_get_first_child(root);
       root;
       root = ssh_xml_dom_node_get_next(root))
    {
      if (ssh_xml_dom_node_get_type(root) != SSH_XML_DOM_NODE_ELEMENT)
        continue;

      /* Check the node name. */
      ucp = ssh_xml_dom_node_get_name(root, &len);
      if (!ssh_xml_match(ucp, len, ssh_custr("alg-av"), 0))
        {
          ssh_ipm_error(ctx, "Invalid element `%s' for AV ALG config", ucp);
          goto error;
        }
      /* Get attributes. */
      attributes = ssh_xml_dom_node_get_attributes(root);

      /* Fetch attributes */
      attr_count =0;
      for(i = 0; i < sizeof(attr_names)/sizeof(attr_names[0]); i++)
        {
          param_tbl[i] =
            ssh_xml_get_attr_value(attributes, attr_names[i], 0, NULL);
          if (param_tbl[i])
            attr_count++;
        }

      if (ssh_adt_num_objects(attributes) > attr_count)
        ssh_ipm_warning(ctx, "Unkown attributes");

      i = ssh_appgw_av_config(config, param_tbl);
      if (i < SSH_APPGW_AV_NUM_PARAMS)
        {
          ssh_ipm_error(ctx, "Attribute %s error", attr_names[i]);
          goto error;
        }
    }

  /* Marshal configuration data. */
  *config_return
    = ssh_appgw_av_config_marshal(config, config_len_return);
  if (*config_return == NULL)
    {
      ssh_ipm_error(ctx, "Could not allocate AV ALG configuration data");
      goto error;
    }

  /* We are done with the config object. */
  ssh_appgw_av_config_destroy(config);

  /* All done. */
  return TRUE;


  /* Error handling. */

 error:

  ssh_appgw_av_config_destroy(config);

  return FALSE;
}
#endif /* WITH_AV_ALG */
#endif /* SSHDIST_AV */
