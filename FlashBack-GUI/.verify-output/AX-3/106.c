/* =====================================================
 *  Path 106
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - formAdvGetLanIp (arg=1, call_ea=0x524ac, func_ea=0x51d54, label=certain)
 *        call: GetValue("wans.wanwebip", cgi_debug);
 *    - formSetSafeWanWebMan (arg=1, call_ea=0x53eb8, func_ea=0x53dcc, label=needs_check)
 *        call: SetValue("wans.wanwebip", v6);
 *    - websGetVar (arg=ret, call_ea=0x53e54, func_ea=source, label=source)
 *        call: v6 = websGetVar(wp, "remoteIp", &byte_794DF);
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


/* Function: formSetSafeWanWebMan @ 0x53DCC */
void __fastcall formSetSafeWanWebMan(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r10
  char_t *v5; // r9
  char_t *v6; // r8
  char_t *v7; // r5
  int v8; // r0
  int v9; // r2
  char ret_buf[64]; // [sp+0h] [bp-40h] BYREF
  char param_str[256]; // [sp+40h] [bp+0h] BYREF

  memset(ret_buf, 0, sizeof(ret_buf));
  memset(param_str, 0, sizeof(param_str));
  Var = websGetVar(wp, "wan_ssl_en", &byte_794DF);
  v5 = websGetVar(wp, "remoteWebEn", &byte_794DF);
  v6 = websGetVar(wp, "remoteIp", &byte_794DF);
  v7 = websGetVar(wp, "remotePort", &byte_794DF);
  SetValue("wans.wanwebsslen", Var);
  SetValue("wans.wanweben", v5);
  if ( *v6 )
  {
    SetValue("wans.wanwebip", v6);
    guest_ip_conflict_handle(v6, "255.255.255.255", 8);
  }
  else
  {
    SetValue("wans.wanwebip", "0.0.0.0");
  }
  v8 = SetValue("wans.wanwebport", v7);
  if ( CommitCfm(v8) )
  {
    sprintf(param_str, "advance_type=%d", 3);
    send_msg_to_netctrl(5, param_str);
    v9 = 0;
  }
  else
  {
    v9 = 1;
  }
  sprintf(ret_buf, "{\"errCode\":%d}", v9);
  websTransfer(wp, ret_buf);
}
