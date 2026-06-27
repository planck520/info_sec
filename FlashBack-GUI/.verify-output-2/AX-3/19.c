/* =====================================================
 *  Path 19
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = websGetVar
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - R7WebsSecurityHandler (arg=1, call_ea=0x28428, func_ea=0x27984, label=certain)
 *        call: strcpy(pcookie, Var);
 *    - websGetVar (arg=ret, call_ea=0x2835c, func_ea=source, label=source)
 *        call: Var = websGetVar(wp, "password", &byte_794DF);
 * ===================================================== */


/* Function: R7WebsSecurityHandler @ 0x27984 */
// local variable allocation has failed, the output may be wrong!
int __fastcall R7WebsSecurityHandler(
        webs_t wp,
        char_t *urlPrefix,
        char_t *webDir,
        int arg,
        char_t *url,
        char_t *path,
        char_t *query)
{
  websRec *ipaddr; // r7
  void *v9; // r0
  int lan_ifname; // r0
  char *v11; // r0
  char *v12; // r0
  const void *v13; // r10
  char_t *cookie; // r0
  char *v15; // r0
  const char *v16; // r10
  char *v17; // r0
  in_addr_t v18; // r1
  size_t v19; // r0
  login_ip_time *v20; // r6
  int v21; // r0
  char *v22; // r1
  char *v23; // r0
  int v24; // r10
  in_addr_t v25; // r1
  char_t *Var; // r5
  char_t *v27; // r0
  bool v28; // zf
  int v29; // r8
  login_ip_time *v30; // r3
  websRec *v31; // r2
  unsigned __int8 *v32; // r0
  websSSL_t *v33; // r1
  int v34; // r8
  login_error_info *v35; // r5
  void *v36; // r0
  time_t v37; // r0
  char *v38; // r0
  int v39; // r7
  char_t *v40; // r5
  int j; // r10
  int v42; // r8
  login_ip_time *v43; // r3
  websRec *v44; // r2
  unsigned __int8 *buf; // r0
  websSSL_t *wsp; // r1
  int v47; // r5
  time_t v48; // r8
  login_error_info *v49; // r6
  int v50; // r9
  int k; // r11
  int last_err_time; // r3
  int login_err_counts; // r3
  login_error_info *v54; // r5
  login_error_info *v55; // r3
  unsigned __int8 *v56; // r0
  unsigned __int8 *servp; // r1
  login_error_info *v58; // r5
  int v59; // r3
  char_t *v61; // [sp+0h] [bp-3E0h]
  char_t *v62; // [sp+0h] [bp-3E0h]
  int i; // [sp+Ch] [bp-3D4h]
  int s; // [sp+1Ch] [bp-3C4h]
  char_t lan_ip_v4[64]; // [sp+20h] [bp-3C0h] OVERLAPPED BYREF
  char pcookie[128]; // [sp+60h] [bp-380h] BYREF
  char urlbuf[256]; // [sp+E0h] [bp-300h] BYREF
  char http_true_passwd[256]; // [sp+1E0h] [bp-200h] BYREF
  char pagetmp[256]; // [sp+2E0h] [bp-100h] BYREF
  char file_path[516]; // [sp+3E0h] [bp+0h] BYREF

  memset(urlbuf, 0, sizeof(urlbuf));
  ipaddr = (websRec *)wp->ipaddr;
  memset(pcookie, 0, sizeof(pcookie));
  memset(http_true_passwd, 0, sizeof(http_true_passwd));
  memset(file_path, 0, 0x200u);
  if ( check_is_ipv6(wp->ipaddr) )
  {
    memset(lan_ip_v4, 0, 0x20u);
    v9 = memset(pagetmp, 0, 0x40u);
    lan_ifname = ifaddrs_get_lan_ifname(v9);
    ifaddrs_get_ifip(lan_ifname, lan_ip_v4);
    sprintf(pagetmp, "http://%s", lan_ip_v4);
    printf("[%s:%d]websRedirect %s.....\n", "R7WebsSecurityHandler", 974, pagetmp);
    if ( !strstr(url, "goform/") )
    {
LABEL_130:
      v22 = pagetmp;
      goto LABEL_68;
    }
    if ( strstr(url, "fast_setting_wifi_set") )
    {
      printf("tim[%s][%d] ipv6 fast wifi seting \n", "R7WebsSecurityHandler", 979);
      return 0;
    }
    websWrite(wp, v61);
LABEL_89:
    websWrite(wp, v62);
    websDone(wp, 200);
    return 0;
  }
  for ( i = 0; i != 3; ++i )
  {
    if ( !strcmp(loginUserInfo[i].ip, wp->ipaddr) )
      break;
  }
  strncpy(urlbuf, url, 0xFFu);
  v11 = strchr(urlbuf, 63);
  if ( v11 )
    *v11 = 0;
  if ( !strncmp(url, "/public/", 8u)
    || !strncmp(url, "/lang/", 6u)
    || strstr(url, "img/main-logo.png")
    || strstr(url, "reasy-ui-1.0.3.js")
    || !strncmp(url, "/favicon.ico", 0xCu)
    || !wp->url
    || !strncmp(url, "/kns-query", 0xAu)
    || !strncmp(url, "/wdinfo.php", 0xBu)
    || strlen(url) == 1 && *url == 47 )
  {
    return 0;
  }
  if ( !strncmp(url, "/redirect.html", 0xEu)
    || !strncmp(url, "/goform/getRebootStatus", 0x17u)
    || !strncmp(url, "/goform/getLoginInfo", 0x14u)
    || i == 3 && !strncmp(url, "/loginerr.html", 0xEu) )
  {
    return 0;
  }
  if ( strlen(urlbuf) > 3 )
  {
    v12 = strchr(urlbuf, 46);
    if ( v12 )
    {
      v13 = v12 + 1;
      if ( !memcmp(v12 + 1, "gif", 3u)
        || !memcmp(v13, "png", 3u)
        || !memcmp(v13, "js", 2u)
        || !memcmp(v13, "css", 3u)
        || !memcmp(v13, "jpg", 3u)
        || !memcmp(v13, "jpeg", 4u)
        || !memcmp(v13, "eot", 3u)
        || !memcmp(v13, "svg", 3u)
        || !memcmp(v13, "ttf", 3u)
        || !memcmp(v13, "woff", 4u) )
      {
        sprintf(file_path, "/webroot%s", urlbuf);
        if ( !access(file_path, 0) )
          return 0;
      }
    }
  }
  if ( strncmp(url, "/goform/telnet", 0xEu) && strncmp(url, "/goform/ate", 0xBu) )
  {
    if ( i == 3 )
      goto LABEL_77;
    if ( !g_Pass[0] )
      goto NOPASSWORD;
LABEL_47:
    cookie = wp->cookie;
    if ( cookie && (v15 = strstr(cookie, "password=")) != 0 )
    {
      v16 = v15 + 9;
      v17 = strrchr(wp->ipaddr, 46);
      s = atoi(v17 + 1);
      v18 = inet_addr(wp->ipaddr) % 0x50;
      sprintf(http_true_passwd, "%s%s%s", g_Pass, &expired_cookie_option[4 * s], &cookie_suffix[4 * v18]);
      if ( v16 )
      {
        v19 = strlen(http_true_passwd);
        if ( !strncmp(v16, http_true_passwd, v19) )
        {
          if ( check_CSRF_attack(wp) )
          {
            printf("[%s %d]#### is attack\n##### wp->refer:\n", "R7WebsSecurityHandler", 1111);
LABEL_133:
            websError(wp, 400, v61);
            return 0;
          }
          if ( !memcmp(urlbuf, "/login.html", 0xAu)
            || !memcmp(urlbuf, "/login.asp", 0xAu)
            || !memcmp(urlbuf, "/loginerr.html", 0xEu)
            || !memcmp(urlbuf, "/login/Auth", 0xBu)
            || strlen(urlbuf) == 1 && urlbuf[0] == 47 )
          {
            goto LOGINOK;
          }
          if ( memcmp(urlbuf, "/logout/Auth", 0xCu) )
          {
            if ( !strncmp(urlbuf, "/goform/GetRouterStatus", 0x17u) )
              return 0;
            if ( !strncmp(urlbuf, "/goform/getWanParameters", 0x18u) )
              return 0;
            v21 = strncmp(urlbuf, "/goform/GetUSBStatus", 0x14u);
            if ( !v21 )
              return 0;
            loginUserInfo[i].time = system_get_uptime(v21);
            if ( !is_web_html(urlbuf) || !need_enter_quick_setting_web() || !strcmp("/index.html", urlbuf) )
            {
              if ( !is_web_html(urlbuf) || need_enter_quick_setting_web() )
                return 0;
              goto LABEL_71;
            }
LABEL_67:
            v22 = "index.html";
LABEL_68:
            websRedirect(wp, v22);
            return 0;
          }
          goto LABEL_60;
        }
      }
    }
    else
    {
      v23 = strrchr(wp->ipaddr, 46);
      v24 = atoi(v23 + 1);
      v25 = inet_addr(wp->ipaddr) % 0x50;
      sprintf(http_true_passwd, "%s%s%s", g_Pass, &expired_cookie_option[4 * v24], &cookie_suffix[4 * v25]);
    }
    if ( !g_Pass[0] )
      goto NOPASSWORD;
LABEL_60:
    v20 = &loginUserInfo[i];
    memset(v20, 0, 0x28u);
    v20->time = 0;
ERROREXIT:
    if ( !strstr(url, "/goform/WifiApScan") )
    {
      if ( !g_Pass[0] )
      {
        v22 = "/";
        goto LABEL_68;
      }
      goto LABEL_91;
    }
    goto LABEL_88;
  }
  if ( !g_Pass[0] )
    return 0;
  if ( i != 3 )
    goto LABEL_47;
LABEL_77:
  if ( loginUserInfo[0].ip[0] && loginUserInfo[1].ip[0] && loginUserInfo[2].ip[0] )
    goto LABEL_80;
  if ( !g_Pass[0] )
  {
    if ( !memcmp(urlbuf, "/error.asp", 0xAu) )
      return 0;
NOPASSWORD:
    for ( j = 0; j != 3; ++j )
    {
      if ( !strcmp(loginUserInfo[j].ip, wp->ipaddr) )
      {
        loginUserInfo[j].time = system_get_uptime(0);
        goto LABEL_131;
      }
    }
    v42 = (unsigned __int8)loginUserInfo[0].ip[0];
    if ( loginUserInfo[0].ip[0] )
    {
      if ( loginUserInfo[1].ip[0] )
      {
        if ( loginUserInfo[2].ip[0] )
          goto LABEL_80;
        v42 = 2;
        v43 = &loginUserInfo[2];
      }
      else
      {
        v42 = 1;
        v43 = &loginUserInfo[1];
      }
    }
    else
    {
      v43 = loginUserInfo;
    }
    v44 = (websRec *)wp->ipaddr;
    do
    {
      buf = v44->header.buf;
      v44 = (websRec *)((char *)v44 + 8);
      wsp = v44[-1].wsp;
      *(_DWORD *)v43->ip = buf;
      *(_DWORD *)&v43->ip[4] = wsp;
      v43 = (login_ip_time *)((char *)v43 + 8);
    }
    while ( v44 != (websRec *)&wp->host_str );
    loginUserInfo[v42].time = system_get_uptime(buf);
LABEL_131:
    if ( check_CSRF_attack(wp) )
    {
      printf("[%s %d]#### is attack\n##### wp->refer:%s\n", "R7WebsSecurityHandler", 1405, wp->referer);
      goto LABEL_133;
    }
    if ( !memcmp(urlbuf, "/login.html", 0xAu)
      || !memcmp(urlbuf, "/login.asp", 0xAu)
      || !memcmp(urlbuf, "/loginerr.html", 0xEu)
      || !memcmp(urlbuf, "/login/Auth", 0xBu)
      || strlen(urlbuf) == 1 && urlbuf[0] == 47 )
    {
      goto LOGINOK;
    }
    if ( !is_web_html(urlbuf) || !need_enter_quick_setting_web() || !strcmp("/index.html", urlbuf) )
    {
      if ( !is_web_html(urlbuf) || need_enter_quick_setting_web() )
        return 0;
LABEL_71:
      if ( strcmp("/index.html", urlbuf) )
        return 0;
      v22 = "main.html";
      goto LABEL_68;
    }
    goto LABEL_67;
  }
  if ( !memcmp(urlbuf, "/login.html", 0xAu)
    || !memcmp(urlbuf, "/login.asp", 0xAu)
    || !memcmp(urlbuf, "/loginerr.html", 0xEu) )
  {
    return 0;
  }
  if ( strlen(urlbuf) == 1 && urlbuf[0] == 47 )
  {
LABEL_91:
    v22 = "login.html";
    goto LABEL_68;
  }
  if ( memcmp(urlbuf, "/login/Auth", 0xBu) )
    goto ERROREXIT;
  Var = websGetVar(wp, "password", &byte_794DF);
  v27 = websGetVar(wp, "username", &byte_794DF);
  v28 = Var == 0;
  if ( Var )
    v28 = v27 == 0;
  if ( v28 )
    goto ERROREXIT;
  if ( strcmp(v27, g_User) || strcmp(Var, g_Pass) )
  {
    v47 = -1;
    v48 = time(0);
    v49 = g_loginErrorInfo;
    v50 = 0;
    for ( k = 0; k != 32; ++k )
    {
      if ( v47 == -1 && !v49->ip[0] )
        v47 = k;
      if ( !strcmp(v49->ip, wp->ipaddr) )
      {
        last_err_time = v49->last_err_time;
        if ( last_err_time && v48 - last_err_time > 180 )
          v49->login_err_counts = 0;
        login_err_counts = v49->login_err_counts;
        v49->last_err_time = v48;
        v49->login_err_counts = ++login_err_counts;
        if ( login_err_counts > 4 )
        {
          v54 = &g_loginErrorInfo[k];
          v54->lock_status = 1;
          v54->lock_time = v48;
          websWrite(wp, v61);
          goto LABEL_89;
        }
        v50 = 1;
      }
      ++v49;
    }
    if ( ((v50 ^ 1) & (v47 != -1)) != 0 )
    {
      v55 = &g_loginErrorInfo[v47];
      do
      {
        v56 = ipaddr->header.buf;
        servp = ipaddr->header.servp;
        ipaddr = (websRec *)((char *)ipaddr + 8);
        *(_DWORD *)v55->ip = v56;
        *(_DWORD *)&v55->ip[4] = servp;
        v55 = (login_error_info *)((char *)v55 + 8);
      }
      while ( ipaddr != (websRec *)&wp->ipaddr[32] );
      v58 = &g_loginErrorInfo[v47];
      v59 = v58->login_err_counts;
      v58->last_err_time = v48;
      v58->login_err_counts = v59 + 1;
    }
LABEL_88:
    websWrite(wp, v61);
    goto LABEL_89;
  }
  SetValue("sys.userpass", g_Pass);
  v29 = (unsigned __int8)loginUserInfo[0].ip[0];
  if ( loginUserInfo[0].ip[0] )
  {
    if ( loginUserInfo[1].ip[0] )
    {
      if ( loginUserInfo[2].ip[0] )
      {
LABEL_80:
        memset(pagetmp, 0, sizeof(pagetmp));
        sprintf(pagetmp, "loginerr.html?%d", 3);
        goto LABEL_130;
      }
      v29 = 2;
      v30 = &loginUserInfo[2];
    }
    else
    {
      v29 = 1;
      v30 = &loginUserInfo[1];
    }
  }
  else
  {
    v30 = loginUserInfo;
  }
  v31 = (websRec *)wp->ipaddr;
  do
  {
    v32 = v31->header.buf;
    v31 = (websRec *)((char *)v31 + 8);
    v33 = v31[-1].wsp;
    *(_DWORD *)v30->ip = v32;
    *(_DWORD *)&v30->ip[4] = v33;
    v30 = (login_ip_time *)((char *)v30 + 8);
  }
  while ( v31 != (websRec *)&wp->host_str );
  loginUserInfo[v29].time = system_get_uptime(v32);
  strcpy(pcookie, Var);
LOGINOK:
  v34 = 0;
  while ( 1 )
  {
    v35 = &g_loginErrorInfo[v34];
    v36 = (void *)strcmp(v35->ip, wp->ipaddr);
    if ( !v36 )
      break;
    if ( ++v34 == 32 )
      goto LABEL_110;
  }
  v36 = memset(v35, 0, 0x20u);
  v35->login_err_counts = 0;
  v35->lock_time = 0;
  v35->lock_status = 0;
  v35->last_err_time = 0;
LABEL_110:
  system_get_uptime(v36);
  strcpy(lan_ip_v4, "main.html");
  memset(&lan_ip_v4[10], 0, 0x36u);
  if ( need_enter_quick_setting_web() )
    strcpy(lan_ip_v4, "index.html");
  if ( stat_0("/webroot/main.html", (struct stat *)pagetmp) == -1 )
    strcpy(lan_ip_v4, "simple_upgrade.asp");
  v37 = time(0);
  srand(v37);
  v38 = strrchr(wp->ipaddr, 46);
  v39 = atoi(v38 + 1);
  expired_cookie_option[4 * v39] = rand() % 26 + 97;
  v40 = &expired_cookie_option[4 * v39];
  v40[1] = rand() % 26 + 97;
  v40[2] = rand() % 26 + 97;
  websRedirectOpCookie(wp, lan_ip_v4, pcookie, 1u);
  return 0;
}
