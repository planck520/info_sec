/* =====================================================
 *  Path 107
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - fromGetIpMacBind (arg=1, call_ea=0x53314, func_ea=0x5315c, label=certain)
 *        call: GetValue("dhcps.Staticnum", mib_value);
 *    - fromSetIpMacBind (arg=1, call_ea=0x53c94, func_ea=0x53974, label=needs_check)
 *        call: v5 = SetValue("dhcps.Staticnum", nptr);
 *    - websGetVar (arg=ret, call_ea=0x539d8, func_ea=source, label=source)
 *        call: nptr = websGetVar(wp, "bindnum", "0");
 * ===================================================== */


/* Function: fromGetIpMacBind @ 0x5315C */
void __fastcall fromGetIpMacBind(webs_t wp, char_t *path, char_t *query)
{
  char *v3; // r0
  cJSON *Object; // r9
  cJSON *v5; // r0
  cJSON *v6; // r0
  cJSON *v7; // r2
  int v8; // r6
  char *mac; // r4
  char *v10; // r0
  cJSON *Array; // r6
  char *v12; // r4
  char *v13; // r10
  in_addr_t v14; // r0
  int v15; // r5
  int v16; // r3
  int v17; // r0
  size_t v18; // r0
  bool v19; // cc
  int v20; // r5
  cJSON *v21; // r5
  cJSON *v22; // r0
  cJSON *v23; // r0
  cJSON *v24; // r2
  const char *v25; // r1
  char *v26; // r0
  cJSON *v27; // r0
  cJSON *v28; // r6
  char *ipaddr; // r4
  int v30; // r3
  cJSON *v31; // r5
  cJSON *v32; // r0
  cJSON *v33; // r0
  const char *v34; // r0
  cJSON *v35; // r0
  const char *v36; // r0
  cJSON *v37; // r0
  char *v38; // r4
  char_t *v39; // [sp-7008h] [bp-800Ch] BYREF
  int v40; // [sp+0h] [bp-1004h]
  const char *v41; // [sp+4h] [bp-1000h]
  char *v42; // [sp+8h] [bp-FFCh]
  char *v43; // [sp+Ch] [bp-FF8h]
  char *v44; // [sp+10h] [bp-FF4h]
  char *v45; // [sp+14h] [bp-FF0h]
  char *string; // [sp+18h] [bp-FECh]
  int i; // [sp+1Ch] [bp-FE8h]
  const char *v48; // [sp+20h] [bp-FE4h]
  char *format; // [sp+24h] [bp-FE0h]
  char *client_mac_buf; // [sp+28h] [bp-FDCh]
  webs_t wpa; // [sp+2Ch] [bp-FD8h]
  unsigned int static_num; // [sp+30h] [bp-FD4h]
  DHCPS_CLIENT_LIST_STRU *plist; // [sp+34h] [bp-FD0h]
  unsigned int client_mac_count; // [sp+38h] [bp-FCCh] BYREF
  int v55; // [sp+3Ch] [bp-FC8h] BYREF
  char ipstr[16]; // [sp+40h] [bp-FC4h] BYREF
  char macstr[16]; // [sp+50h] [bp-FB4h] BYREF
  char v58[16]; // [sp+60h] [bp-FA4h] BYREF
  char v59[16]; // [sp+70h] [bp-F94h] BYREF
  char lan_dhhtpd_ip[32]; // [sp+80h] [bp-F84h] BYREF
  char mib_name[64]; // [sp+A0h] [bp-F64h] BYREF
  char mib_value[128]; // [sp+E0h] [bp-F24h] BYREF
  char v63[128]; // [sp+160h] [bp-EA4h] BYREF
  DHCPS_CLIENT_LIST_STRU static_list[32]; // [sp+1E0h] [bp-E24h] BYREF

  wpa = wp;
  memset(mib_name, 0, sizeof(mib_name));
  memset(mib_value, 0, sizeof(mib_value));
  memset(lan_dhhtpd_ip, 0, sizeof(lan_dhhtpd_ip));
  client_mac_count = 0;
  v3 = (char *)malloc(0x5000u);
  client_mac_buf = v3;
  if ( v3 )
    get_online_client_info(v3, &client_mac_count);
  Object = cJSON_CreateObject();
  GetValue("lan.ip", mib_value);
  v5 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "lanIp", v5);
  memset(mib_value, 0, sizeof(mib_value));
  GetValue("lan.mask", mib_value);
  v6 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "lanMask", v6);
  memset(mib_value, 0, sizeof(mib_value));
  if ( ifaddrs_get_ifip("br0:dname", lan_dhhtpd_ip) >= 0 )
    v7 = cJSON_CreateString(lan_dhhtpd_ip);
  else
    v7 = cJSON_CreateString("0.0.0.0");
  cJSON_AddItemToObject(Object, "dhttpIP", v7);
  plist = (DHCPS_CLIENT_LIST_STRU *)&v39;
  memset(ipstr, 0, sizeof(ipstr));
  memset(macstr, 0, sizeof(macstr));
  v8 = 0;
  memset(static_list, 0, sizeof(static_list));
  mac = static_list[0].mac;
  GetValue("dhcps.Staticnum", mib_value);
  static_num = atoi(mib_value);
  format = "dhcps.Staticip%d";
  v48 = "%[^;];%17[0-9a-fA-F:];%*s";
  while ( v8 != static_num )
  {
    sprintf(mib_name, format, ++v8);
    GetValue(mib_name, mib_value);
    if ( _isoc99_sscanf(mib_value, v48, ipstr, macstr) == 2 )
    {
      *((_DWORD *)mac + 9) = 0;
      i = 0;
      v10 = str2low(macstr, 16);
      strncpy(mac, v10, 0x12u);
      strncpy(mac + 18, ipstr, 0x10u);
      memset(mib_value, i, sizeof(mib_value));
      get_device_name(mib_value, mac);
      strcpy(mac + 40, mib_value);
      *((_DWORD *)mac - 2) = 1;
    }
    mac += 112;
  }
  Array = cJSON_CreateArray();
  cJSON_AddItemToObject(Object, "dhcpClientList", Array);
  if ( file_get_dhcps_clients_list(plist, 256) )
  {
    printf(
      "Error->%s: %s(%d)--file_get_dhcps_clients_list returns error!\n",
      "/home/work/workspace/UGW6.0_P/prod/httpd/11ac/cgi/lan_dhcp_clients.c",
      "fromGetIpMacBind",
      363);
  }
  else
  {
    format = (char *)client_mac_count;
    memset(v58, 0, sizeof(v58));
    memset(v59, 0, sizeof(v59));
    v55 = 0;
    memset(v63, 0, sizeof(v63));
    GetValue("wl.guest.dhcps_ip", v58);
    GetValue("lan.gst.1.mask", v59);
    v48 = (const char *)bswap32(inet_addr(v58));
    i = bswap32(inet_addr(v59));
    if ( Array )
    {
      v12 = plist->mac;
      v13 = plist[257].mac;
      string = "ipaddr";
      v45 = "macaddr";
      v44 = "status";
      v43 = "1";
      v42 = "0";
      v41 = "devname";
      do
      {
        if ( !*((_DWORD *)v12 + 9) )
          break;
        v14 = inet_addr(v12 + 18);
        if ( ((bswap32(v14) ^ (unsigned int)v48) & i) != 0
          && (!format || find_onlinemac_client(client_mac_buf, format, &v55, v12)) )
        {
          v15 = 0;
          v16 = 112;
          while ( (int)static_num > v15 )
          {
            v40 = v16;
            v17 = strcmp(v12, &static_list[0].mac[v16 * v15]);
            v16 = v40;
            if ( !v17 )
              break;
            ++v15;
          }
          if ( v12[40] )
          {
            v18 = strlen(v12 + 40);
            if ( !memcmp(v12 + 40, "(null)", v18) )
              strcpy(v12 + 40, &byte_794DF);
          }
          v19 = (int)static_num <= v15;
          v20 = v15;
          if ( v19 )
          {
            plist[v20].bound = dhcps_bound_type::AUTO_ALLOCATION;
            v21 = cJSON_CreateObject();
            cJSON_AddItemToArray(Array, v21);
            v22 = cJSON_CreateString(v12 + 18);
            cJSON_AddItemToObject(v21, string, v22);
            v23 = cJSON_CreateString(v12);
            cJSON_AddItemToObject(v21, v45, v23);
            memset(v63, 0, sizeof(v63));
            get_device_name(v63, v12);
            if ( v63[0] )
            {
              v24 = cJSON_CreateString(v63);
              v25 = "devname";
            }
            else
            {
              v24 = cJSON_CreateString(v12 + 40);
              v25 = v41;
            }
            cJSON_AddItemToObject(v21, v25, v24);
            if ( *((_DWORD *)v12 - 2) )
              v26 = v42;
            else
              v26 = v43;
            v27 = cJSON_CreateString(v26);
            cJSON_AddItemToObject(v21, v44, v27);
          }
          else
          {
            static_list[v20].bound = dhcps_bound_type::AUTO_ALLOCATION;
            if ( !static_list[v20].hostname[0] )
              strcpy(static_list[v20].hostname, v12 + 40);
          }
        }
        v12 += 112;
      }
      while ( v12 != v13 );
    }
  }
  v28 = cJSON_CreateArray();
  cJSON_AddItemToObject(Object, "bindList", v28);
  ipaddr = static_list[0].ipaddr;
  v30 = 0;
  plist = (DHCPS_CLIENT_LIST_STRU *)"ipaddr";
  format = "macaddr";
  v48 = "0";
  while ( v30 != static_num )
  {
    i = v30;
    v31 = cJSON_CreateObject();
    cJSON_AddItemToArray(v28, v31);
    v32 = cJSON_CreateString(ipaddr);
    cJSON_AddItemToObject(v31, (const char *)plist, v32);
    v33 = cJSON_CreateString(ipaddr - 18);
    cJSON_AddItemToObject(v31, format, v33);
    v34 = ipaddr + 22;
    ipaddr += 112;
    v35 = cJSON_CreateString(v34);
    cJSON_AddItemToObject(v31, "devname", v35);
    if ( *(_DWORD *)(ipaddr - 138) )
      v36 = v48;
    else
      v36 = "1";
    v37 = cJSON_CreateString(v36);
    cJSON_AddItemToObject(v31, "status", v37);
    v30 = i + 1;
  }
  v38 = cJSON_Print(Object);
  cJSON_Delete(Object);
  websWrite(wpa, v39);
  websWrite(wpa, v39);
  free(v38);
  free(client_mac_buf);
  websDone(wpa, 200);
}


/* Function: fromSetIpMacBind @ 0x53974 */
void __fastcall fromSetIpMacBind(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r5
  unsigned int v5; // r0
  int i; // r4
  char *v7; // r0
  const char *v8; // r1
  int v9; // r3
  int v10; // r5
  int v11; // r2
  int v12; // r2
  int old_static_num; // [sp+8h] [bp-448h]
  char *nptr; // [sp+Ch] [bp-444h]
  int v15; // [sp+10h] [bp-440h]
  char v16[32]; // [sp+28h] [bp-428h] BYREF
  char v17[32]; // [sp+48h] [bp-408h] BYREF
  char mib_name[64]; // [sp+68h] [bp-3E8h] BYREF
  char v19[64]; // [sp+A8h] [bp-3A8h] BYREF
  char v20[64]; // [sp+E8h] [bp-368h] BYREF
  char mib_value[128]; // [sp+128h] [bp-328h] BYREF
  char s[128]; // [sp+1A8h] [bp-2A8h] BYREF
  char ret_buf[256]; // [sp+228h] [bp-228h] BYREF
  char param_str[256]; // [sp+328h] [bp-128h] BYREF

  memset(ret_buf, 0, sizeof(ret_buf));
  memset(mib_name, 0, sizeof(mib_name));
  memset(mib_value, 0, sizeof(mib_value));
  nptr = websGetVar(wp, "bindnum", "0");
  Var = websGetVar(wp, "list", &byte_794DF);
  GetValue("dhcps.Staticnum", mib_value);
  v15 = atoi(mib_value);
  v5 = atoi(nptr);
  old_static_num = v5;
  if ( v5 > 0x20 )
  {
    printf("staic ip number over %d\n", 32);
    goto LABEL_30;
  }
  for ( i = 1; ; ++i )
  {
    v9 = (int)Var;
    if ( Var )
      v9 = 1;
    if ( i > old_static_num )
      v9 = 0;
    if ( !v9 )
      break;
    memset(s, 0, sizeof(s));
    memset(v19, 0, sizeof(v19));
    memset(param_str, 0, 0x80u);
    memset(v16, 0, sizeof(v16));
    memset(v17, 0, sizeof(v17));
    memset(v20, 0, sizeof(v20));
    v7 = strchr(Var, 10);
    if ( v7 )
    {
      v8 = Var;
      Var = v7 + 1;
      *v7 = 0;
      strcpy(s, v8);
    }
    else
    {
      strcpy(s, Var);
    }
    if ( s[0] == 13 )
    {
      if ( _isoc99_sscanf(&s[1], "%17[0-9a-fA-F:]\r%s", v16, v17) != 2 )
        goto LABEL_20;
      strcpy(v20, &byte_794DF);
    }
    else if ( _isoc99_sscanf(s, "%[^\r]\r%[0-9a-fA-F:]\r%s", v20, v16, v17) != 3 )
    {
LABEL_20:
      v5 = puts("get ip and mac error!");
      v9 = 1;
      break;
    }
    printf("%s %d# dev_name=%s,mac_addr=%s,ip_addr=%s\n", "set_mac_bind_list", 430, v20, v16, v17);
    sprintf(v19, "dhcps.Staticip%d", i);
    sprintf(param_str, "%s;%s;0", v17, v16);
    v5 = SetValue(v19, param_str);
    if ( v20[0] )
    {
      memset(v19, 0, sizeof(v19));
      memset(param_str, 0, 0x80u);
      v5 = set_device_name(v20, v16);
    }
  }
  v10 = old_static_num + 1;
  if ( i == old_static_num + 1 )
  {
    if ( !v9 )
    {
      puts("set static num sucess!");
      v5 = SetValue("dhcps.Staticnum", nptr);
      while ( v10 <= v15 )
      {
        memset(mib_value, 0, sizeof(mib_value));
        sprintf(mib_name, "dhcps.Staticip%d", v10);
        GetValue(mib_name, mib_value);
        v11 = v10++;
        sprintf(mib_name, "dhcps.Staticip%d", v11);
        v5 = SetValue(mib_name, &byte_794DF);
      }
      goto LABEL_27;
    }
LABEL_30:
    v12 = 1;
    goto Finish;
  }
  if ( v9 )
    goto LABEL_30;
LABEL_27:
  if ( CommitCfm(v5) )
  {
    memset(param_str, 0, sizeof(param_str));
    sprintf(param_str, "op=%d,index=1", 6);
    send_msg_to_netctrl(3, param_str);
  }
  v12 = 0;
Finish:
  sprintf(ret_buf, "{\"errCode\":%d}", v12);
  websTransfer(wp, ret_buf);
}
