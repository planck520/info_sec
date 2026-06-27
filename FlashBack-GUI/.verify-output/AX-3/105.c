/* =====================================================
 *  Path 105
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - formAdvGetLanIp (arg=1, call_ea=0x523ec, func_ea=0x51d54, label=certain)
 *        call: GetValue("vpn.cli.type", clientType);
 *    - formSetPPTPClient (arg=1, call_ea=0x4a3d8, func_ea=0x4a210, label=needs_check)
 *        call: SetValue("vpn.cli.type", v5);
 *    - websGetVar (arg=ret, call_ea=0x4a264, func_ea=source, label=source)
 *        call: v5 = websGetVar(wp, "clientType", "pptp");
 * ===================================================== */


/* Function: formAdvGetLanIp @ 0x51D54 */
// local variable allocation has failed, the output may be wrong!
void __fastcall formAdvGetLanIp(webs_t wp, char_t *path, char_t *query)
{
  int v3; // r4
  int v4; // r0
  cJSON *Object; // r4
  cJSON *String; // r0
  cJSON *v7; // r0
  cJSON *v8; // r0
  cJSON *v9; // r0
  cJSON *v10; // r0
  cJSON *v11; // r0
  cJSON *v12; // r0
  cJSON *v13; // r0
  cJSON *v14; // r0
  cJSON *v15; // r0
  cJSON *v16; // r0
  cJSON *v17; // r0
  cJSON *v18; // r0
  cJSON *v19; // r0
  cJSON *v20; // r0
  cJSON *v21; // r0
  cJSON *v22; // r0
  cJSON *v23; // r0
  int v24; // r5
  int v25; // r0
  cJSON *v26; // r0
  cJSON *v27; // r0
  cJSON *v28; // r0
  cJSON *v29; // r0
  const char *v30; // r0
  char *v31; // r1
  cJSON *v32; // r0
  void *v33; // r0
  const char *wifi_workmode; // r0
  cJSON *v35; // r0
  cJSON *v36; // r0
  char *v37; // r5
  char_t *fmt; // [sp+0h] [bp-5Ch]
  char_t *fmta; // [sp+0h] [bp-5Ch]
  char dhen[4]; // [sp+30h] [bp-2Ch] BYREF
  char clientType[8]; // [sp+34h] [bp-28h] BYREF
  char lan_ip[16]; // [sp+3Ch] [bp-20h] BYREF
  char lan_mask[16]; // [sp+4Ch] [bp-10h] BYREF
  char sys_mode[16]; // [sp+5Ch] [bp+0h] BYREF
  char conn_type[16]; // [sp+6Ch] [bp+10h] BYREF
  char dhcps_lease_time[16]; // [sp+7Ch] [bp+20h] BYREF
  char wl_mode[16]; // [sp+8Ch] [bp+30h] BYREF
  char lan_dns1[32]; // [sp+9Ch] [bp+40h] BYREF
  char lan_dns2[32]; // [sp+BCh] [bp+60h] BYREF
  char lan_dns_auto[32]; // [sp+DCh] [bp+80h] BYREF
  char dips[32]; // [sp+FCh] [bp+A0h] BYREF
  char dipe[32]; // [sp+11Ch] [bp+C0h] BYREF
  char wanIp[32]; // [sp+13Ch] [bp+E0h] BYREF
  char wanMask[32]; // [sp+15Ch] [bp+100h] BYREF
  char serverip[32]; // [sp+17Ch] [bp+120h] BYREF
  char vlan2ip[32]; // [sp+19Ch] [bp+140h] BYREF
  char vlan2mask[32]; // [sp+1BCh] [bp+160h] BYREF
  char pptpSvrIp[32]; // [sp+1DCh] [bp+180h] BYREF
  char vpnCliIp[32]; // [sp+1FCh] [bp+1A0h] BYREF
  char ifaddr[32]; // [sp+21Ch] [bp+1C0h] BYREF
  char cgi_debug[32]; // [sp+23Ch] [bp+1E0h] OVERLAPPED BYREF
  char guestLanIp[64]; // [sp+25Ch] [bp+200h] BYREF
  char guestLanMask[64]; // [sp+29Ch] [bp+240h] BYREF
  char wan_num[128]; // [sp+2DCh] [bp+280h] BYREF
  WAN_STATUS_INFO_STRU wan_status; // [sp+35Ch] [bp+300h] BYREF

  memset(lan_ip, 0, sizeof(lan_ip));
  memset(lan_mask, 0, sizeof(lan_mask));
  memset(sys_mode, 0, sizeof(sys_mode));
  memset(conn_type, 0, sizeof(conn_type));
  memset(lan_dns1, 0, sizeof(lan_dns1));
  memset(lan_dns2, 0, sizeof(lan_dns2));
  memset(lan_dns_auto, 0, sizeof(lan_dns_auto));
  memset(wan_num, 0, sizeof(wan_num));
  GetValue("wan1.connecttype", conn_type);
  GetValue("sys.mode", sys_mode);
  memset(&wan_status, 0, sizeof(wan_status));
  v3 = atoi(conn_type);
  v4 = atoi(sys_mode);
  file_wan_status_info_get(0, v3, 1, v4, &wan_status);
  GetValue("lan.ip", lan_ip);
  GetValue("lan.mask", lan_mask);
  Object = cJSON_CreateObject();
  String = cJSON_CreateString(lan_ip);
  cJSON_AddItemToObject(Object, "lanIp", String);
  v7 = cJSON_CreateString(lan_mask);
  cJSON_AddItemToObject(Object, "lanMask", v7);
  v8 = cJSON_CreateString(wan_status.ip_info.wan_ip);
  cJSON_AddItemToObject(Object, "ip", v8);
  v9 = cJSON_CreateString(wan_status.ip_info.wan_mask);
  cJSON_AddItemToObject(Object, "mask", v9);
  GetValue("dhcps.en", dhen);
  GetValue("dhcps.start", dips);
  GetValue("dhcps.end", dipe);
  GetValue("dhcps.leasetime", dhcps_lease_time);
  v10 = cJSON_CreateString(dips);
  cJSON_AddItemToObject(Object, "startIp", v10);
  v11 = cJSON_CreateString(dipe);
  cJSON_AddItemToObject(Object, "endIp", v11);
  v12 = cJSON_CreateString(dhcps_lease_time);
  cJSON_AddItemToObject(Object, "leaseTime", v12);
  v13 = cJSON_CreateString(dhen);
  cJSON_AddItemToObject(Object, "dhcpEn", v13);
  GetValue("lan.dns.hand1", lan_dns1);
  GetValue("lan.dns.hand2", lan_dns2);
  GetValue("lan.dns.auto", lan_dns_auto);
  v14 = cJSON_CreateString(lan_dns_auto);
  cJSON_AddItemToObject(Object, "lanDnsAuto", v14);
  v15 = cJSON_CreateString(lan_dns1);
  cJSON_AddItemToObject(Object, "lanDns1", v15);
  v16 = cJSON_CreateString(lan_dns2);
  cJSON_AddItemToObject(Object, "lanDns2", v16);
  memset(guestLanIp, 0, sizeof(guestLanIp));
  memset(guestLanMask, 0, sizeof(guestLanMask));
  GetValue("wl.guest.dhcps_ip", guestLanIp);
  GetValue("wl.guest.dhcps_mask", guestLanMask);
  v17 = cJSON_CreateString(guestLanIp);
  cJSON_AddItemToObject(Object, "guestIp", v17);
  v18 = cJSON_CreateString(guestLanMask);
  cJSON_AddItemToObject(Object, "guestMask", v18);
  memset(wanIp, 0, sizeof(wanIp));
  memset(wanMask, 0, sizeof(wanMask));
  memset(serverip, 0, sizeof(serverip));
  memset(vlan2ip, 0, sizeof(vlan2ip));
  memset(vlan2mask, 0, sizeof(vlan2mask));
  cgiGetWanIpAndMask(wanIp, wanMask, serverip, vlan2ip, vlan2mask);
  v19 = cJSON_CreateString(serverip);
  cJSON_AddItemToObject(Object, "serverIp", v19);
  v20 = cJSON_CreateString(vlan2ip);
  cJSON_AddItemToObject(Object, "vlan2Ip", v20);
  v21 = cJSON_CreateString(vlan2mask);
  cJSON_AddItemToObject(Object, "vlan2Mask", v21);
  v22 = cJSON_CreateString(wanIp);
  cJSON_AddItemToObject(Object, "wanIp", v22);
  v23 = cJSON_CreateString(wanMask);
  cJSON_AddItemToObject(Object, "wanMask", v23);
  GetValue("wans.flag", wan_num);
  if ( atoi(wan_num) == 2 )
  {
    memset(&wan_status, 0, sizeof(wan_status));
    memset(conn_type, 0, sizeof(conn_type));
    GetValue("wan2.connecttype", conn_type);
    v24 = atoi(conn_type);
    v25 = atoi(sys_mode);
    file_wan_status_info_get(0, v24, 2, v25, &wan_status);
    v26 = cJSON_CreateString(wan_status.ip_info.wan_ip);
    cJSON_AddItemToObject(Object, "wanIp2", v26);
    v27 = cJSON_CreateString(wan_status.ip_info.wan_mask);
    cJSON_AddItemToObject(Object, "wanMask2", v27);
    memset(cgi_debug, 0, 0x10u);
    if ( GetValue("cgi_debug", cgi_debug) )
    {
      if ( !strcmp("on", cgi_debug) )
        printf(
          "%s[%s:%s:%d] %sdouble wan is enabled, get info of wan2: ip == %s, mask == %s\n\x1B[0m",
          "\x1B[0;33m",
          "cgi",
          "formAdvGetLanIp",
          474,
          "\x1B[0;32m",
          wan_status.ip_info.wan_ip,
          wan_status.ip_info.wan_mask);
    }
  }
  memset(pptpSvrIp, 0, sizeof(pptpSvrIp));
  GetValue("vpn.ser.pptpserver", pptpSvrIp);
  v28 = cJSON_CreateString(pptpSvrIp);
  cJSON_AddItemToObject(Object, "pptpSvrIp", v28);
  v29 = cJSON_CreateString("255.255.255.0");
  cJSON_AddItemToObject(Object, "pptpSvrMask", v29);
  memset(vpnCliIp, 0, sizeof(vpnCliIp));
  memset(clientType, 0, sizeof(clientType));
  memset(ifaddr, 0, sizeof(ifaddr));
  GetValue("vpn.cli.type", clientType);
  if ( !strcmp(clientType, "pptp") )
  {
    v30 = "ppp0";
  }
  else
  {
    if ( strcmp(clientType, "l2tp") )
      goto LABEL_9;
    v30 = "ppp45";
  }
  if ( ifaddrs_get_ifip(v30, ifaddr) < 0 )
  {
LABEL_9:
    v31 = "0.0.0.0";
    goto LABEL_10;
  }
  v31 = ifaddr;
LABEL_10:
  strcpy(vpnCliIp, v31);
  v32 = cJSON_CreateString(vpnCliIp);
  cJSON_AddItemToObject(Object, "vpnCliIp", v32);
  v33 = memset(wl_mode, 0, sizeof(wl_mode));
  wifi_workmode = (const char *)get_wifi_workmode(v33);
  strcpy(wl_mode, wifi_workmode);
  v35 = cJSON_CreateString(wl_mode);
  cJSON_AddItemToObject(Object, "wl_mode", v35);
  memset(cgi_debug, 0, sizeof(cgi_debug));
  GetValue("wans.wanwebip", cgi_debug);
  v36 = cJSON_CreateString(cgi_debug);
  cJSON_AddItemToObject(Object, "remoteIp", v36);
  v37 = cJSON_Print(Object);
  cJSON_Delete(Object);
  websWrite(wp, fmt);
  websWrite(wp, fmta);
  free(v37);
  websDone(wp, 200);
}


/* Function: formSetPPTPClient @ 0x4A210 */
void __fastcall formSetPPTPClient(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r6
  char_t *v5; // r5
  int v6; // r7
  int v7; // r6
  int v8; // r0
  char *v9; // r1
  int v10; // r3
  char_t *v11; // r11
  char_t *v12; // r8
  char_t *v13; // r9
  int v14; // r0
  const char *v15; // r0
  int v16; // r0
  void *v17; // r0
  const char *v18; // r0
  int v19; // r0
  int v20; // r0
  const char *wifi_workmode; // r0
  char_t *fmt; // [sp+0h] [bp-20h]
  char_t *fmta; // [sp+0h] [bp-20h]
  char_t *v24; // [sp+4h] [bp-1Ch]
  char_t *vpn_type; // [sp+Ch] [bp-14h]
  char_t *v26; // [sp+10h] [bp-10h]
  int v27; // [sp+14h] [bp-Ch]
  int v28; // [sp+18h] [bp-8h] BYREF
  int v29; // [sp+1Ch] [bp-4h] BYREF
  char cli_type_prev[8]; // [sp+20h] [bp+0h] BYREF
  char param_str[256]; // [sp+28h] [bp+8h] BYREF

  memset(cli_type_prev, 0, sizeof(cli_type_prev));
  Var = websGetVar(wp, "clientEn", "0");
  v5 = websGetVar(wp, "clientType", "pptp");
  GetValue("vpn.cli.type", cli_type_prev);
  if ( strcmp(Var, "0") )
  {
    if ( strcmp(Var, "1") || !v5 )
      goto finish;
    if ( !strcmp(v5, "pptp") )
    {
      v10 = 1;
    }
    else
    {
      if ( strcmp(v5, "l2tp") )
        goto finish;
      v10 = 2;
    }
    v27 = v10;
    SetValue("vpn.cli.type", v5);
    v28 = 0;
    v29 = 0;
    *(_DWORD *)param_str = 0;
    *(_DWORD *)&param_str[4] = 0;
    v11 = websGetVar(wp, "domain", &byte_794DF);
    vpn_type = websGetVar(wp, "clientMppe", "0");
    v26 = websGetVar(wp, "clientMppeOp", "128");
    v12 = websGetVar(wp, "userName", &byte_794DF);
    v13 = websGetVar(wp, "password", &byte_794DF);
    fmt = websGetVar(wp, "clientIp", &byte_794DF);
    v24 = websGetVar(wp, "clientMask", &byte_794DF);
    GetValue("vpn.cli.l2tpEnable", &v29);
    GetValue("vpn.cli.pptpEnable", &v28);
    if ( !strcmp(Var, "1") && (!*v11 || !*v12 || !*v13) )
      goto finish;
    if ( v27 == 2 )
    {
      SetValue("vpn.cli.l2tpEnable", Var);
      v20 = strcmp((const char *)&v28, "0");
      if ( v20 )
      {
        v7 = 1;
        v20 = SetValue("vpn.cli.pptpEnable", "0");
      }
      else
      {
        v7 = 0;
      }
      wifi_workmode = (const char *)get_wifi_workmode(v20);
      if ( !strcmp("wisp", wifi_workmode) )
        snprintf(param_str, 8u, "%d", 5);
      else
        snprintf(param_str, 8u, "%d", 1);
      SetValue("vpn.cli.l2tpwanid", param_str);
      v6 = 1;
      SetValue("vpn.cli.l2tpPUN", v12);
      SetValue("vpn.cli.l2tpPPW", v13);
      SetValue("vpn.cli.l2tpservIP", v11);
      SetValue("vpn.cli.l2tpnetseg", fmt);
      v16 = SetValue("vpn.cli.l2tpnetmsk", v24);
    }
    else
    {
      SetValue("vpn.cli.pptpEnable", Var);
      v14 = strcmp((const char *)&v29, "0");
      if ( v14 )
      {
        v6 = 1;
        v14 = SetValue("vpn.cli.l2tpEnable", "0");
      }
      else
      {
        v6 = 0;
      }
      v15 = (const char *)get_wifi_workmode(v14);
      if ( !strcmp("wisp", v15) )
        snprintf(param_str, 8u, "%d", 5);
      else
        snprintf(param_str, 8u, "%d", 1);
      SetValue("vpn.cli.pptpwanid", param_str);
      v7 = 1;
      SetValue("vpn.cli.pptpMPPE", vpn_type);
      SetValue("vpn.cli.pptpMPPE.op", v26);
      SetValue("vpn.cli.pptpPUN", v12);
      SetValue("vpn.cli.pptpPPW", v13);
      SetValue("vpn.cli.pptpservIP", v11);
      SetValue("vpn.cli.pptpnetseg", fmt);
      v16 = SetValue("vpn.cli.pptpnetmsk", v24);
    }
    enable_gro(v16);
    v9 = "1";
    goto LABEL_30;
  }
  v28 = 0;
  v29 = 0;
  *(_DWORD *)param_str = 0;
  GetValue("vpn.cli.l2tpEnable", &v29);
  GetValue("vpn.cli.pptpEnable", &v28);
  GetValue("vpn.ser.pptpdEnable", param_str);
  if ( !strcmp((const char *)&v29, "0") )
  {
    v6 = 0;
  }
  else
  {
    v6 = 1;
    SetValue("vpn.cli.l2tpEnable", "0");
  }
  if ( !strcmp((const char *)&v28, "0") )
  {
    v7 = 0;
  }
  else
  {
    v7 = 1;
    SetValue("vpn.cli.pptpEnable", "0");
  }
  v8 = strcmp(param_str, "0");
  if ( !v8 )
  {
    v9 = "0";
LABEL_30:
    v8 = SetValue("inet_gro_disable", v9);
  }
  if ( !CommitCfm(v8) )
    goto finish;
  v17 = memset(param_str, 0, sizeof(param_str));
  v18 = (const char *)get_wifi_workmode(v17);
  if ( !strcmp("wisp", v18) )
    sprintf(param_str, "op=%d,wan_id=%d", 3, 5);
  else
    sprintf(param_str, "op=%d,wan_id=%d", 3, 1);
  if ( !strcmp(cli_type_prev, "pptp") && !strcmp(v5, "l2tp") || strcmp(cli_type_prev, "l2tp") || strcmp(v5, "pptp") )
  {
    if ( v7 == 1 )
      send_msg_to_netctrl(22, param_str);
    if ( v6 == 1 )
    {
      v19 = 23;
LABEL_48:
      send_msg_to_netctrl(v19, param_str);
    }
  }
  else
  {
    if ( v6 == 1 )
      send_msg_to_netctrl(23, param_str);
    if ( v7 == 1 )
    {
      v19 = 22;
      goto LABEL_48;
    }
  }
finish:
  websWrite(wp, fmt);
  websWrite(wp, fmta);
  websDone(wp, 200);
}
