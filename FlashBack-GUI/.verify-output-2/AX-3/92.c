/* =====================================================
 *  Path 92
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - formGetIPv6status (arg=1, call_ea=0x61024, func_ea=0x60b48, label=certain)
 *        call: GetValue("ipv6.wan.route", value);
 *    - formSetIPv6status (arg=1, call_ea=0x62b88, func_ea=0x62228, label=needs_check)
 *        call: SetValue("ipv6.wan.route", v191);
 *    - websGetVar (arg=ret, call_ea=0x62478, func_ea=source, label=source)
 *        call: v191 = websGetVar(wp, "gateWay", &byte_794DF);
 * ===================================================== */


/* Function: formGetIPv6status @ 0x60B48 */
void __fastcall formGetIPv6status(webs_t wp, char_t *path, char_t *query)
{
  cJSON *Object; // r5
  FILE *v6; // r0
  FILE *v7; // r9
  cJSON *String; // r0
  const char *wan_ipv6_connect_type; // r0
  cJSON *v10; // r0
  FILE *v11; // r0
  FILE *v12; // r7
  cJSON *v13; // r0
  FILE *v14; // r0
  FILE *v15; // r7
  cJSON *v16; // r0
  FILE *v17; // r0
  FILE *v18; // r7
  cJSON *v19; // r0
  FILE *v20; // r0
  FILE *v21; // r7
  FILE *v22; // r0
  FILE *v23; // r7
  cJSON *v24; // r0
  int ipv6_wan_ifname; // r0
  cJSON *v26; // r0
  FILE *v27; // r0
  FILE *v28; // r8
  cJSON *v29; // r0
  FILE *v30; // r0
  FILE *v31; // r8
  cJSON *v32; // r0
  FILE *v33; // r0
  FILE *v34; // r8
  cJSON *v35; // r0
  FILE *v36; // r0
  FILE *v37; // r8
  cJSON *v38; // r0
  FILE *v39; // r0
  FILE *v40; // r8
  cJSON *v41; // r0
  FILE *v42; // r0
  FILE *v43; // r8
  cJSON *v44; // r0
  FILE *v45; // r0
  FILE *v46; // r8
  cJSON *v47; // r0
  FILE *v48; // r0
  FILE *v49; // r8
  FILE *v50; // r0
  FILE *v51; // r10
  int v52; // r0
  int wlan_mode; // r0
  int v54; // r0
  const char *v55; // r0
  FILE *v56; // r0
  FILE *v57; // r10
  int v58; // r10
  cJSON *v59; // r0
  FILE *v60; // r0
  FILE *v61; // r8
  cJSON *v62; // r0
  FILE *v63; // r0
  FILE *v64; // r8
  FILE *v65; // r0
  FILE *v66; // r8
  cJSON *v67; // r0
  FILE *v68; // r0
  FILE *v69; // r8
  cJSON *v70; // r0
  FILE *v71; // r0
  FILE *v72; // r8
  cJSON *v73; // r0
  FILE *v74; // r0
  FILE *v75; // r8
  FILE *v76; // r0
  FILE *v77; // r8
  cJSON *v78; // r0
  FILE *v79; // r0
  FILE *v80; // r8
  char *lan_ipv6_connect_type; // r0
  cJSON *v82; // r0
  int lan_ifname; // r0
  int if_addr6; // r0
  int i; // r3
  int v86; // r8
  cJSON *v87; // r2
  FILE *v88; // r0
  FILE *v89; // r7
  const char *v90; // r0
  cJSON *v91; // r0
  FILE *v92; // r0
  FILE *v93; // r7
  FILE *v94; // r0
  FILE *v95; // r7
  cJSON *v96; // r2
  FILE *v97; // r0
  FILE *v98; // r7
  cJSON *v99; // r0
  char *v100; // r4
  FILE *v101; // r0
  FILE *v102; // r6
  char_t *fmt; // [sp+0h] [bp-8E0h]
  char_t *fmta; // [sp+0h] [bp-8E0h]
  void *s; // [sp+10h] [bp-8D0h]
  char prefix_len[8]; // [sp+2Ch] [bp-8B4h] BYREF
  char sys_mode[16]; // [sp+34h] [bp-8ACh] BYREF
  char lan_ip[16]; // [sp+44h] [bp-89Ch] BYREF
  char lan_mask[16]; // [sp+54h] [bp-88Ch] BYREF
  char ipv6lantype[32]; // [sp+64h] [bp-87Ch] BYREF
  char value[128]; // [sp+84h] [bp-85Ch] BYREF
  char buf[128]; // [sp+104h] [bp-7DCh] BYREF
  char str_addr[128]; // [sp+184h] [bp-75Ch] BYREF
  char mib_name[128]; // [sp+204h] [bp-6DCh] BYREF
  WAN_STATUS_INFO_STRU wan_status; // [sp+284h] [bp-65Ch] BYREF
  ipv6_addr_struct addr_list[16]; // [sp+378h] [bp-568h] BYREF
  char mib_value[1024]; // [sp+4B8h] [bp-428h] BYREF

  memset(value, 0, sizeof(value));
  memset(buf, 0, sizeof(buf));
  memset(str_addr, 0, sizeof(str_addr));
  memset(prefix_len, 0, sizeof(prefix_len));
  memset(ipv6lantype, 0, sizeof(ipv6lantype));
  memset(mib_name, 0, sizeof(mib_name));
  memset(mib_value, 0, sizeof(mib_value));
  memset(sys_mode, 0, sizeof(sys_mode));
  memset(lan_ip, 0, sizeof(lan_ip));
  memset(lan_mask, 0, sizeof(lan_mask));
  printf("[%s] path:%s query:%s\n", "formGetIPv6status", path, query);
  Object = cJSON_CreateObject();
  GetValue("ipv6.enable", value);
  v6 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v7 = v6;
  if ( v6 )
  {
    fprintf(v6, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 274, "ipv6.enable", value);
    fclose(v7);
  }
  else
  {
    puts("error");
  }
  String = cJSON_CreateString(value);
  cJSON_AddItemToObject(Object, "IPv6En", String);
  wan_ipv6_connect_type = cgi_get_wan_ipv6_connect_type();
  v10 = cJSON_CreateString(wan_ipv6_connect_type);
  cJSON_AddItemToObject(Object, "conType", v10);
  GetValue("wan1.ppoe.userid", value);
  v11 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v12 = v11;
  if ( v11 )
  {
    fprintf(v11, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 283, "wan1.ppoe.userid", value);
    fclose(v12);
  }
  else
  {
    puts("error");
  }
  v13 = cJSON_CreateString(value);
  cJSON_AddItemToObject(Object, "ISPusername", v13);
  GetValue("wan1.ppoe.pwd", value);
  v14 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v15 = v14;
  if ( v14 )
  {
    fprintf(v14, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 287, "wan1.ppoe.pwd", value);
    fclose(v15);
  }
  else
  {
    puts("error");
  }
  v16 = cJSON_CreateString(value);
  cJSON_AddItemToObject(Object, "ISPpassword", v16);
  GetValue("ipv6.wan.d6c.iapd", value);
  v17 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v18 = v17;
  if ( v17 )
  {
    fprintf(v17, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 292, "ipv6.wan.d6c.iapd", value);
    fclose(v18);
  }
  else
  {
    puts("error");
  }
  v19 = cJSON_CreateString(value);
  cJSON_AddItemToObject(Object, "prefixDelegate", v19);
  GetValue("ipv6.wan.addr", value);
  v20 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v21 = v20;
  if ( v20 )
  {
    fprintf(v20, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 297, "ipv6.wan.addr", value);
    fclose(v21);
  }
  else
  {
    puts("error");
  }
  GetValue("ipv6.wan.prefix_len", prefix_len);
  v22 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v23 = v22;
  if ( v22 )
  {
    fprintf(v22, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 298, "ipv6.wan.prefix_len", prefix_len);
    fclose(v23);
  }
  else
  {
    puts("error");
  }
  snprintf(buf, 0x7Fu, "%s/%s", value, prefix_len);
  v24 = cJSON_CreateString(buf);
  cJSON_AddItemToObject(Object, "wanAddr", v24);
  ipv6_wan_ifname = get_ipv6_wan_ifname();
  get_if_addr6(ipv6_wan_ifname, addr_list, 16);
  inet_ntop(10, addr_list, str_addr, 0x80u);
  snprintf(buf, 0x7Fu, "%s/%d", str_addr, addr_list[0].prefix_len);
  v26 = cJSON_CreateString(buf);
  cJSON_AddItemToObject(Object, "wanipcheck", v26);
  GetValue("ipv6.wan.route", value);
  v27 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v28 = v27;
  if ( v27 )
  {
    fprintf(v27, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 313, "ipv6.wan.route", value);
    fclose(v28);
  }
  else
  {
    puts("error");
  }
  v29 = cJSON_CreateString(value);
  cJSON_AddItemToObject(Object, "gateWay", v29);
  GetValue("ipv6.wan.dns1", value);
  v30 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v31 = v30;
  if ( v30 )
  {
    fprintf(v30, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 318, "ipv6.wan.dns1", value);
    fclose(v31);
  }
  else
  {
    puts("error");
  }
  v32 = cJSON_CreateString(value);
  cJSON_AddItemToObject(Object, "wanPreDNS", v32);
  GetValue("ipv6.wan.dns2", value);
  v33 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v34 = v33;
  if ( v33 )
  {
    fprintf(v33, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 322, "ipv6.wan.dns2", value);
    fclose(v34);
  }
  else
  {
    puts("error");
  }
  v35 = cJSON_CreateString(value);
  cJSON_AddItemToObject(Object, "wanAltDNS", v35);
  GetValue("lan.ip", lan_ip);
  v36 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v37 = v36;
  if ( v36 )
  {
    fprintf(v36, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 326, "lan.ip", lan_ip);
    fclose(v37);
  }
  else
  {
    puts("error");
  }
  v38 = cJSON_CreateString(lan_ip);
  cJSON_AddItemToObject(Object, "lanIp", v38);
  GetValue("lan.mask", lan_mask);
  v39 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v40 = v39;
  if ( v39 )
  {
    fprintf(v39, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 329, "lan.mask", lan_mask);
    fclose(v40);
  }
  else
  {
    puts("error");
  }
  v41 = cJSON_CreateString(lan_mask);
  cJSON_AddItemToObject(Object, "lanMask", v41);
  GetValue("wl.guest.dhcps_ip", value);
  v42 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v43 = v42;
  if ( v42 )
  {
    fprintf(v42, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 333, "wl.guest.dhcps_ip", value);
    fclose(v43);
  }
  else
  {
    puts("error");
  }
  v44 = cJSON_CreateString(value);
  cJSON_AddItemToObject(Object, "guestIp", v44);
  GetValue("wl.guest.dhcps_mask", value);
  v45 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v46 = v45;
  if ( v45 )
  {
    fprintf(v45, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 336, "wl.guest.dhcps_mask", value);
    fclose(v46);
  }
  else
  {
    puts("error");
  }
  v47 = cJSON_CreateString(value);
  cJSON_AddItemToObject(Object, "guestMask", v47);
  memset(mib_name, 0, sizeof(mib_name));
  memset(mib_value, 0, sizeof(mib_value));
  sprintf(mib_name, "wan%d.connecttype", 1);
  GetValue(mib_name, mib_value);
  v48 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v49 = v48;
  if ( v48 )
  {
    fprintf(v48, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 344, mib_name, mib_value);
    fclose(v49);
  }
  else
  {
    puts("error");
  }
  s = (void *)atoi(mib_value);
  memset(&wan_status, 0, sizeof(wan_status));
  GetValue("sys.mode", sys_mode);
  v50 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v51 = v50;
  if ( v50 )
  {
    fprintf(v50, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 347, "sys.mode", sys_mode);
    v52 = fclose(v51);
  }
  else
  {
    v52 = puts("error");
  }
  wlan_mode = get_wlan_mode(v52);
  if ( wlan_mode )
  {
    if ( wlan_mode != 1 )
      goto LABEL_65;
    GetValue("wl.wisp.access_mode", mib_value);
    v56 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v57 = v56;
    if ( v56 )
    {
      fprintf(v56, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 359, "wl.wisp.access_mode", mib_value);
      fclose(v57);
    }
    else
    {
      puts("error");
    }
    if ( !strcmp(mib_value, "dhcp") )
    {
      v58 = 0;
    }
    else if ( !strcmp(mib_value, "static") )
    {
      v58 = 1;
    }
    else if ( !strcmp(mib_value, "pppoe") )
    {
      v58 = 2;
    }
    else
    {
      v58 = 0;
    }
    memset(&wan_status.ip_info, 0, 0x10u);
    if ( wifi_wisp_get_ip_info(v58, &wan_status.ip_info) )
      puts("get WISP MODE wan status error!");
    if ( !file_wan_status_info_get(1, v58, 5, 2, &wan_status) )
      goto LABEL_65;
    v55 = "get WISP MODE wan status error!";
    goto LABEL_64;
  }
  v54 = atoi(sys_mode);
  if ( file_wan_status_info_get(0, s, 1, v54, &wan_status) )
  {
    v55 = "get ROUTER MODE wan status error!";
LABEL_64:
    puts(v55);
  }
LABEL_65:
  v59 = cJSON_CreateString(wan_status.ip_info.wan_ip);
  cJSON_AddItemToObject(Object, "wanIp", v59);
  GetValue("ipv6.tun6in4.remoteip", value);
  v60 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v61 = v60;
  if ( v60 )
  {
    fprintf(v60, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 386, "ipv6.tun6in4.remoteip", value);
    fclose(v61);
  }
  else
  {
    puts("error");
  }
  v62 = cJSON_CreateString(value);
  cJSON_AddItemToObject(Object, "inRemoteIP", v62);
  GetValue("ipv6.tun6in4.itfip", value);
  v63 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v64 = v63;
  if ( v63 )
  {
    fprintf(v63, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 390, "ipv6.tun6in4.itfip", value);
    fclose(v64);
  }
  else
  {
    puts("error");
  }
  GetValue("ipv6.tun6in4.itfiplen", prefix_len);
  v65 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v66 = v65;
  if ( v65 )
  {
    fprintf(v65, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 391, "ipv6.tun6in4.itfiplen", prefix_len);
    fclose(v66);
  }
  else
  {
    puts("error");
  }
  snprintf(buf, 0x7Fu, "%s/%s", value, prefix_len);
  v67 = cJSON_CreateString(buf);
  cJSON_AddItemToObject(Object, "intfIPv6", v67);
  GetValue("ipv6.tun6rd.remoteip", value);
  v68 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v69 = v68;
  if ( v68 )
  {
    fprintf(v68, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 396, "ipv6.tun6rd.remoteip", value);
    fclose(v69);
  }
  else
  {
    puts("error");
  }
  v70 = cJSON_CreateString(value);
  cJSON_AddItemToObject(Object, "rdRemoteIP", v70);
  GetValue("ipv6.tun6rd.remotemask", value);
  v71 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v72 = v71;
  if ( v71 )
  {
    fprintf(v71, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 400, "ipv6.tun6rd.remotemask", value);
    fclose(v72);
  }
  else
  {
    puts("error");
  }
  v73 = cJSON_CreateString(value);
  cJSON_AddItemToObject(Object, "wanMask", v73);
  GetValue("ipv6.tun6rd.prefixv6", value);
  v74 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v75 = v74;
  if ( v74 )
  {
    fprintf(v74, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 404, "ipv6.tun6rd.prefixv6", value);
    fclose(v75);
  }
  else
  {
    puts("error");
  }
  GetValue("ipv6.tun6rd.prefixv6.len", prefix_len);
  v76 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v77 = v76;
  if ( v76 )
  {
    fprintf(v76, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 405, "ipv6.tun6rd.prefixv6.len", prefix_len);
    fclose(v77);
  }
  else
  {
    puts("error");
  }
  snprintf(buf, 0x7Fu, "%s/%s", value, prefix_len);
  v78 = cJSON_CreateString(buf);
  cJSON_AddItemToObject(Object, "netIPv6", v78);
  GetValue("ipv6.lan.type", value);
  v79 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v80 = v79;
  if ( v79 )
  {
    fprintf(v79, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 411, "ipv6.lan.type", value);
    fclose(v80);
  }
  else
  {
    puts("error");
  }
  lan_ipv6_connect_type = cgi_get_lan_ipv6_connect_type(ipv6lantype);
  v82 = cJSON_CreateString(lan_ipv6_connect_type);
  cJSON_AddItemToObject(Object, "lanType", v82);
  lan_ifname = ifaddrs_get_lan_ifname();
  if_addr6 = get_if_addr6(lan_ifname, addr_list, 16);
  for ( i = 0; i < if_addr6; ++i )
  {
    v86 = i;
    if ( (addr_list[i].addr.__u6_addr32[0] & 0xC0FF) != 0x80FE )
    {
      inet_ntop(10, &addr_list[i], value, 0x80u);
      snprintf(buf, 0x7Fu, "%s/%d", value, addr_list[v86].prefix_len);
      v87 = cJSON_CreateString(buf);
      goto LABEL_95;
    }
  }
  v87 = cJSON_CreateString(&byte_794DF);
LABEL_95:
  cJSON_AddItemToObject(Object, "lanAddr", v87);
  GetValue("ipv6.lan.prefix_auto", value);
  v88 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v89 = v88;
  if ( v88 )
  {
    fprintf(v88, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 434, "ipv6.lan.prefix_auto", value);
    fclose(v89);
  }
  else
  {
    puts("error");
  }
  if ( atoi(value) )
    v90 = "auto";
  else
    v90 = "manual";
  v91 = cJSON_CreateString(v90);
  cJSON_AddItemToObject(Object, "prefixType", v91);
  GetValue("ipv6.lan.prefix", value);
  v92 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v93 = v92;
  if ( v92 )
  {
    fprintf(v92, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 442, "ipv6.lan.prefix", value);
    fclose(v93);
  }
  else
  {
    puts("error");
  }
  GetValue("ipv6.lan.prefix_len", prefix_len);
  v94 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v95 = v94;
  if ( v94 )
  {
    fprintf(v94, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 443, "ipv6.lan.prefix_len", prefix_len);
    fclose(v95);
  }
  else
  {
    puts("error");
  }
  if ( !strncmp(value, "2002:", 5u) )
    memset(buf, 0, sizeof(buf));
  else
    snprintf(buf, 0x7Fu, "%s/%s", value, prefix_len);
  v96 = cJSON_CreateString(buf);
  cJSON_AddItemToObject(Object, "lanPrefix", v96);
  GetValue("wan1.connecttype", value);
  v97 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v98 = v97;
  if ( v97 )
  {
    fprintf(v97, "%s(%d): GetValue %s = %s\n", "formGetIPv6status", 456, "wan1.connecttype", value);
    fclose(v98);
  }
  else
  {
    puts("error");
  }
  v99 = cJSON_CreateString(value);
  cJSON_AddItemToObject(Object, "wanType", v99);
  v100 = cJSON_Print(Object);
  v101 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v102 = v101;
  if ( v101 )
  {
    fprintf(v101, "%s(%d): out = \n%s\n", "formGetIPv6status", 469, v100);
    fclose(v102);
  }
  else
  {
    puts("error");
  }
  cJSON_Delete(Object);
  websWrite(wp, fmt);
  websWrite(wp, fmta);
  websDone(wp, 200);
  free(v100);
}


/* Function: formSetIPv6status @ 0x62228 */
void __fastcall formSetIPv6status(webs_t wp, char_t *path, char_t *query)
{
  FILE *v6; // r0
  FILE *v7; // r8
  char_t *Var; // r9
  char_t *v9; // r6
  char_t *v10; // r11
  char_t *v11; // r5
  char_t *v12; // r10
  FILE *v13; // r0
  FILE *v14; // r7
  int WanConnType; // r0
  int wan_ifname_gw; // r0
  FILE *v17; // r0
  FILE *v18; // r6
  FILE *v19; // r0
  FILE *v20; // r6
  FILE *v21; // r0
  FILE *v22; // r6
  int v23; // r3
  FILE *v24; // r0
  FILE *v25; // r6
  FILE *v26; // r0
  FILE *v27; // r6
  FILE *v28; // r0
  FILE *v29; // r6
  FILE *v30; // r0
  FILE *v31; // r6
  FILE *v32; // r0
  FILE *v33; // r0
  FILE *v34; // r6
  FILE *v35; // r0
  FILE *v36; // r6
  FILE *v37; // r0
  FILE *v38; // r6
  FILE *v39; // r0
  FILE *v40; // r6
  FILE *v41; // r0
  FILE *v42; // r6
  FILE *v43; // r0
  FILE *v44; // r6
  FILE *v45; // r0
  FILE *v46; // r6
  FILE *v47; // r0
  FILE *v48; // r0
  FILE *v49; // r6
  FILE *v50; // r0
  FILE *v51; // r6
  FILE *v52; // r0
  FILE *v53; // r5
  FILE *v54; // r0
  FILE *v55; // r5
  FILE *v56; // r0
  FILE *v57; // r5
  FILE *v58; // r0
  FILE *v59; // r5
  FILE *v60; // r0
  FILE *v61; // r0
  FILE *v62; // r6
  FILE *v63; // r0
  FILE *v64; // r6
  FILE *v65; // r0
  FILE *v66; // r5
  FILE *v67; // r0
  FILE *v68; // r6
  FILE *v69; // r0
  FILE *v70; // r6
  FILE *v71; // r0
  FILE *v72; // r6
  FILE *v73; // r0
  FILE *v74; // r0
  FILE *v75; // r9
  FILE *v76; // r0
  FILE *v77; // r9
  FILE *v78; // r0
  FILE *v79; // r5
  FILE *v80; // r0
  FILE *v81; // r5
  FILE *v82; // r0
  FILE *v83; // r9
  FILE *v84; // r0
  FILE *v85; // r5
  FILE *v86; // r0
  FILE *v87; // r5
  FILE *v88; // r0
  FILE *v89; // r5
  FILE *v90; // r0
  FILE *v91; // r8
  FILE *v92; // r0
  FILE *v93; // r5
  int v94; // r5
  int v95; // r0
  FILE *v96; // r0
  FILE *v97; // r5
  FILE *v98; // r0
  FILE *v99; // r5
  FILE *v100; // r0
  FILE *v101; // r6
  FILE *v102; // r0
  FILE *v103; // r6
  FILE *v104; // r0
  char_t *v105; // r6
  char_t *v106; // r7
  char_t *v107; // r10
  char_t *v108; // r9
  char_t *v109; // r8
  FILE *v110; // r0
  FILE *v111; // r11
  FILE *v112; // r0
  FILE *v113; // r7
  FILE *v114; // r0
  FILE *v115; // r0
  FILE *v116; // r0
  FILE *v117; // r0
  FILE *v118; // r8
  FILE *v119; // r0
  FILE *v120; // r8
  int v121; // r8
  FILE *v122; // r0
  FILE *v123; // r7
  FILE *v124; // r0
  FILE *v125; // r7
  FILE *v126; // r0
  FILE *v127; // r7
  FILE *v128; // r0
  FILE *v129; // r9
  FILE *v130; // r0
  FILE *v131; // r7
  FILE *v132; // r0
  FILE *v133; // r0
  FILE *v134; // r9
  FILE *v135; // r0
  FILE *v136; // r10
  FILE *v137; // r0
  FILE *v138; // r10
  int v139; // r0
  int v140; // r7
  FILE *v141; // r0
  FILE *v142; // r9
  FILE *v143; // r0
  FILE *v144; // r9
  FILE *v145; // r0
  FILE *v146; // r9
  FILE *v147; // r0
  FILE *v148; // r9
  FILE *v149; // r0
  FILE *v150; // r9
  FILE *v151; // r0
  FILE *v152; // r9
  FILE *v153; // r0
  FILE *v154; // r9
  FILE *v155; // r0
  FILE *v156; // r9
  int v157; // r2
  FILE *v158; // r0
  FILE *v159; // r11
  FILE *v160; // r0
  FILE *v161; // r11
  FILE *v162; // r0
  FILE *v163; // r11
  FILE *v164; // r0
  FILE *v165; // r11
  FILE *v166; // r0
  FILE *v167; // r10
  FILE *v168; // r0
  FILE *v169; // r10
  FILE *v170; // r0
  FILE *v171; // r10
  FILE *v172; // r0
  FILE *v173; // r10
  FILE *v174; // r0
  FILE *v175; // r10
  FILE *v176; // r0
  FILE *v177; // r10
  FILE *v178; // r0
  FILE *v179; // r10
  FILE *v180; // r0
  FILE *v181; // r10
  FILE *v182; // r0
  FILE *v183; // r10
  FILE *v184; // r0
  FILE *v185; // r10
  FILE *v186; // r0
  FILE *v187; // r10
  int v188; // r5
  int v189; // [sp+1Ch] [bp-51Ch]
  char_t *v190; // [sp+28h] [bp-510h]
  char_t *v191; // [sp+2Ch] [bp-50Ch]
  char_t *v192; // [sp+30h] [bp-508h]
  char_t *v193; // [sp+34h] [bp-504h]
  char_t *v194; // [sp+38h] [bp-500h]
  char_t *v195; // [sp+3Ch] [bp-4FCh]
  char_t *v196; // [sp+40h] [bp-4F8h]
  char_t *v197; // [sp+44h] [bp-4F4h]
  char ipv6_old_flag[4]; // [sp+54h] [bp-4E4h] BYREF
  _DWORD v199[2]; // [sp+58h] [bp-4E0h] BYREF
  _DWORD v200[2]; // [sp+60h] [bp-4D8h] BYREF
  _DWORD v201[2]; // [sp+68h] [bp-4D0h] BYREF
  char v202[16]; // [sp+70h] [bp-4C8h] BYREF
  char v203[16]; // [sp+80h] [bp-4B8h] BYREF
  char s1[64]; // [sp+90h] [bp-4A8h] BYREF
  char v205[64]; // [sp+D0h] [bp-468h] BYREF
  char v206[64]; // [sp+110h] [bp-428h] BYREF
  char v207[64]; // [sp+150h] [bp-3E8h] BYREF
  char s[128]; // [sp+190h] [bp-3A8h] BYREF
  char param_str[256]; // [sp+210h] [bp-328h] BYREF
  char buf[256]; // [sp+310h] [bp-228h] BYREF
  char v211[296]; // [sp+410h] [bp-128h] BYREF

  memset(param_str, 0, sizeof(param_str));
  memset(buf, 0, sizeof(buf));
  *(_WORD *)ipv6_old_flag = 0;
  printf("[%s] path:%s query:%s\n", "formSetIPv6status", path, query);
  GetValue("ipv6.enable", ipv6_old_flag);
  v6 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v7 = v6;
  if ( v6 )
  {
    fprintf(v6, "%s(%d): GetValue %s = %s\n", "formSetIPv6status", 834, "ipv6.enable", ipv6_old_flag);
    fclose(v7);
  }
  else
  {
    puts("error");
  }
  memset(s, 0, sizeof(s));
  memset(v211, 0, 0x80u);
  v201[1] = 0;
  v199[0] = 0;
  v199[1] = 0;
  v200[0] = 0;
  v200[1] = 0;
  v201[0] = 0;
  memset(s1, 0, sizeof(s1));
  memset(v205, 0, sizeof(v205));
  memset(v206, 0, sizeof(v206));
  memset(v202, 0, sizeof(v202));
  memset(v207, 0, sizeof(v207));
  memset(v203, 0, sizeof(v203));
  Var = websGetVar(wp, "IPv6En", "0");
  v9 = websGetVar(wp, "conType", "DHCP");
  v10 = websGetVar(wp, "ISPusername", &byte_794DF);
  v190 = websGetVar(wp, "ISPpassword", &byte_794DF);
  v11 = websGetVar(wp, "prefixDelegate", "1");
  v195 = websGetVar(wp, "wanAddr", &byte_794DF);
  v191 = websGetVar(wp, "gateWay", &byte_794DF);
  v192 = websGetVar(wp, "wanPreDNS", &byte_794DF);
  v193 = websGetVar(wp, "wanAltDNS", &byte_794DF);
  v194 = websGetVar(wp, "wanMask", &byte_794DF);
  v12 = websGetVar(wp, "remoteIP", &byte_794DF);
  v196 = websGetVar(wp, "intfIPv6", &byte_794DF);
  websGetVar(wp, "localIPv6", &byte_794DF);
  v197 = websGetVar(wp, "netIPv6", &byte_794DF);
  websGetVar(wp, "lanMask", &byte_794DF);
  printf(
    "websGetVar:\n"
    " ipv6_en = %s\n"
    " con_type = %s\n"
    " isp_usersname = %s\n"
    "isp_password = %s\n"
    " IAPD = %s\n"
    " wan_addr = %s\n"
    "gateway = %s\n"
    " pre_dns = %s\n"
    " sec_dns = %s\n",
    Var,
    v9,
    v10,
    v190,
    v11,
    v195,
    v191,
    v192,
    v193);
  SetValue("ipv6.enable", Var);
  v13 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v14 = v13;
  if ( v13 )
  {
    fprintf(v13, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 615, "ipv6.enable", Var);
    fclose(v14);
  }
  else
  {
    puts("error");
  }
  if ( !strcmp(Var, "0") )
    goto LABEL_23;
  if ( !strcmp(v9, "6in4") || !strcmp(v9, "6to4") || !strcmp(v9, "6rd") )
  {
    WanConnType = getWanConnType(1);
    wan_ifname_gw = ifaddrs_get_wan_ifname_gw(1, WanConnType);
    if ( wan_ifname_gw )
      ifaddrs_get_ifip(wan_ifname_gw, v203);
  }
  v189 = strcmp(v9, "DHCP");
  if ( !v189 )
  {
    SetValue("ipv6.wan.type", "0dhcp");
    v17 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v18 = v17;
    if ( v17 )
    {
      fprintf(v17, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 634, "ipv6.wan.type", "0dhcp");
      fclose(v18);
    }
    else
    {
      puts("error");
    }
    SetValue("ipv6.wan.auto_dns", "1");
    v19 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v20 = v19;
    if ( v19 )
    {
      fprintf(v19, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 635, "ipv6.wan.auto_dns", "1");
      fclose(v20);
    }
    else
    {
      puts("error");
    }
    SetValue("ipv6.wan.d6c.iapd", v11);
    v21 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v22 = v21;
    if ( v21 )
    {
      fprintf(v21, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 638, "ipv6.wan.d6c.iapd", v11);
LABEL_105:
      v60 = v22;
      goto LABEL_106;
    }
    goto LABEL_22;
  }
  v189 = strcmp(v9, "PPPoE");
  if ( !v189 )
  {
    SetValue("ipv6.wan.type", "1pppoe");
    v24 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v25 = v24;
    if ( v24 )
    {
      fprintf(v24, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 642, "ipv6.wan.type", "1pppoe");
      fclose(v25);
    }
    else
    {
      puts("error");
    }
    SetValue("ipv6.wan.auto_dns", "1");
    v26 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v27 = v26;
    if ( v26 )
    {
      fprintf(v26, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 643, "ipv6.wan.auto_dns", "1");
      fclose(v27);
    }
    else
    {
      puts("error");
    }
    SetValue("ipv6.wan.pppoe.username", v10);
    v28 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v29 = v28;
    if ( v28 )
    {
      fprintf(v28, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 644, "ipv6.wan.pppoe.username", v10);
      fclose(v29);
    }
    else
    {
      puts("error");
    }
    SetValue("ipv6.wan.pppoe.password", v190);
    v30 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v31 = v30;
    if ( v30 )
    {
      fprintf(v30, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 645, "ipv6.wan.pppoe.password", v190);
      fclose(v31);
    }
    else
    {
      puts("error");
    }
    SetValue("ipv6.wan.d6c.iapd", v11);
    v32 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v22 = v32;
    if ( v32 )
    {
      fprintf(v32, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 648, "ipv6.wan.d6c.iapd", v11);
      goto LABEL_105;
    }
    goto LABEL_22;
  }
  if ( !strcmp(v9, "Static") )
  {
    SetValue("ipv6.wan.type", "2static");
    v33 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v34 = v33;
    if ( v33 )
    {
      fprintf(v33, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 652, "ipv6.wan.type", "2static");
      fclose(v34);
    }
    else
    {
      puts("error");
    }
    v189 = parse_addr(v195, s, 128, v199, 8);
    if ( !v189 )
    {
      SetValue("ipv6.wan.addr", s);
      v35 = fopen("/var/ipv6_cgi_debug.log", "a+");
      v36 = v35;
      if ( v35 )
      {
        fprintf(v35, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 658, "ipv6.wan.addr", s);
        fclose(v36);
      }
      else
      {
        puts("error");
      }
      SetValue("ipv6.wan.prefix_len", v199);
      v37 = fopen("/var/ipv6_cgi_debug.log", "a+");
      v38 = v37;
      if ( v37 )
      {
        fprintf(v37, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 659, "ipv6.wan.prefix_len", (const char *)v199);
        fclose(v38);
      }
      else
      {
        puts("error");
      }
      SetValue("ipv6.wan.route", v191);
      v39 = fopen("/var/ipv6_cgi_debug.log", "a+");
      v40 = v39;
      if ( v39 )
      {
        fprintf(v39, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 660, "ipv6.wan.route", v191);
        fclose(v40);
      }
      else
      {
        puts("error");
      }
      SetValue("ipv6.wan.auto_dns", "0");
      v41 = fopen("/var/ipv6_cgi_debug.log", "a+");
      v42 = v41;
      if ( v41 )
      {
        fprintf(v41, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 661, "ipv6.wan.auto_dns", "0");
        fclose(v42);
      }
      else
      {
        puts("error");
      }
      SetValue("ipv6.wan.dns1", v192);
      v43 = fopen("/var/ipv6_cgi_debug.log", "a+");
      v44 = v43;
      if ( v43 )
      {
        fprintf(v43, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 662, "ipv6.wan.dns1", v192);
        fclose(v44);
      }
      else
      {
        puts("error");
      }
      SetValue("ipv6.wan.dns2", v193);
      v45 = fopen("/var/ipv6_cgi_debug.log", "a+");
      v46 = v45;
      if ( v45 )
      {
        fprintf(v45, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 663, "ipv6.wan.dns2", v193);
        fclose(v46);
      }
      else
      {
        puts("error");
      }
      SetValue("ipv6.wan.d6c.iapd", v11);
      v47 = fopen("/var/ipv6_cgi_debug.log", "a+");
      v22 = v47;
      if ( v47 )
      {
        fprintf(v47, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 664, "ipv6.wan.d6c.iapd", v11);
        goto LABEL_105;
      }
      goto LABEL_22;
    }
LABEL_155:
    v23 = 1;
    goto LABEL_156;
  }
  if ( strcmp(v9, "6in4") )
  {
    v189 = strcmp(v9, "6to4");
    if ( !v189 )
    {
      SetValue("ipv6.wan.type", "4tun6to4");
      v61 = fopen("/var/ipv6_cgi_debug.log", "a+");
      v62 = v61;
      if ( v61 )
      {
        fprintf(v61, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 684, "ipv6.wan.type", "4tun6to4");
        fclose(v62);
      }
      else
      {
        puts("error");
      }
      SetValue("ipv6.wan.d6c.iapd", v11);
      v63 = fopen("/var/ipv6_cgi_debug.log", "a+");
      v64 = v63;
      if ( v63 )
      {
        fprintf(v63, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 685, "ipv6.wan.d6c.iapd", v11);
        fclose(v64);
      }
      else
      {
        puts("error");
      }
      SetValue("ipv6.tun6to4.localip", v203);
      v65 = fopen("/var/ipv6_cgi_debug.log", "a+");
      v66 = v65;
      if ( v65 )
      {
        fprintf(v65, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 687, "ipv6.tun6to4.localip", v203);
        fclose(v66);
      }
      else
      {
        puts("error");
      }
      ipv6_calculate_6to4_inf_ip_prefix(v203, s1);
      SetValue("ipv6.tun6to4.itfip", s1);
      v67 = fopen("/var/ipv6_cgi_debug.log", "a+");
      v68 = v67;
      if ( v67 )
      {
        fprintf(v67, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 691, "ipv6.tun6to4.itfip", s1);
        fclose(v68);
      }
      else
      {
        puts("error");
      }
      GetValue("ipv6.lan.prefix", v206);
      v69 = fopen("/var/ipv6_cgi_debug.log", "a+");
      v70 = v69;
      if ( v69 )
      {
        fprintf(v69, "%s(%d): GetValue %s = %s\n", "SetIPv6Wanstatus", 693, "ipv6.lan.prefix", v206);
        fclose(v70);
      }
      else
      {
        puts("error");
      }
      if ( !strcmp(v206, v205) )
        goto LABEL_23;
      SetValue("ipv6.lan.prefix", v205);
      v71 = fopen("/var/ipv6_cgi_debug.log", "a+");
      v72 = v71;
      if ( v71 )
      {
        fprintf(v71, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 697, "ipv6.lan.prefix", v205);
        fclose(v72);
      }
      else
      {
        puts("error");
      }
      SetValue("ipv6.lan.phy.restart", "1");
      v73 = fopen("/var/ipv6_cgi_debug.log", "a+");
      v22 = v73;
      if ( v73 )
      {
        fprintf(v73, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 698, "ipv6.lan.phy.restart", "1");
        goto LABEL_105;
      }
      goto LABEL_22;
    }
    if ( !strcmp(v9, "6rd") )
    {
      v189 = parse_addr(v197, v211, 128, v200, 8);
      if ( !v189 )
      {
        SetValue("ipv6.wan.type", "5tun6rd");
        v74 = fopen("/var/ipv6_cgi_debug.log", "a+");
        v75 = v74;
        if ( v74 )
        {
          fprintf(v74, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 709, "ipv6.wan.type", "5tun6rd");
          fclose(v75);
        }
        else
        {
          puts("error");
        }
        SetValue("ipv6.wan.d6c.iapd", v11);
        v76 = fopen("/var/ipv6_cgi_debug.log", "a+");
        v77 = v76;
        if ( v76 )
        {
          fprintf(v76, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 710, "ipv6.wan.d6c.iapd", v11);
          fclose(v77);
        }
        else
        {
          puts("error");
        }
        SetValue("ipv6.tun6rd.remoteip", v12);
        v78 = fopen("/var/ipv6_cgi_debug.log", "a+");
        v79 = v78;
        if ( v78 )
        {
          fprintf(v78, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 714, "ipv6.tun6rd.remoteip", v12);
          fclose(v79);
        }
        else
        {
          puts("error");
        }
        SetValue("ipv6.tun6rd.remotemask", v194);
        v80 = fopen("/var/ipv6_cgi_debug.log", "a+");
        v81 = v80;
        if ( v80 )
        {
          fprintf(v80, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 715, "ipv6.tun6rd.remotemask", v194);
          fclose(v81);
        }
        else
        {
          puts("error");
        }
        snprintf(v207, 0x40u, "::%s", v12);
        SetValue("ipv6.tun6rd.route", v207);
        v82 = fopen("/var/ipv6_cgi_debug.log", "a+");
        v83 = v82;
        if ( v82 )
        {
          fprintf(v82, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 718, "ipv6.tun6rd.route", v207);
          fclose(v83);
        }
        else
        {
          puts("error");
        }
        SetValue("ipv6.tun6rd.prefixv6", v211);
        v84 = fopen("/var/ipv6_cgi_debug.log", "a+");
        v85 = v84;
        if ( v84 )
        {
          fprintf(v84, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 721, "ipv6.tun6rd.prefixv6", v211);
          fclose(v85);
        }
        else
        {
          puts("error");
        }
        SetValue("ipv6.tun6rd.prefixv6.len", v200);
        v86 = fopen("/var/ipv6_cgi_debug.log", "a+");
        v87 = v86;
        if ( v86 )
        {
          fprintf(
            v86,
            "%s(%d): SetValue %s = %s\n",
            "SetIPv6Wanstatus",
            722,
            "ipv6.tun6rd.prefixv6.len",
            (const char *)v200);
          fclose(v87);
        }
        else
        {
          puts("error");
        }
        SetValue("ipv6.tun6rd.localipv4.ip", v203);
        v88 = fopen("/var/ipv6_cgi_debug.log", "a+");
        v89 = v88;
        if ( v88 )
        {
          fprintf(v88, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 725, "ipv6.tun6rd.localipv4.ip", v203);
          fclose(v89);
        }
        else
        {
          puts("error");
        }
        ipv6_tunnel_calculate_ipv4prefix(v203, v194, v202, 16, v201, 8);
        SetValue("ipv6.tun6rd.localipv4.prefix", v202);
        v90 = fopen("/var/ipv6_cgi_debug.log", "a+");
        v91 = v90;
        if ( v90 )
        {
          fprintf(v90, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 729, "ipv6.tun6rd.localipv4.prefix", v202);
          fclose(v91);
        }
        else
        {
          puts("error");
        }
        SetValue("ipv6.tun6rd.localipv4.prefix.len", v201);
        v92 = fopen("/var/ipv6_cgi_debug.log", "a+");
        v93 = v92;
        if ( v92 )
        {
          fprintf(
            v92,
            "%s(%d): SetValue %s = %s\n",
            "SetIPv6Wanstatus",
            730,
            "ipv6.tun6rd.localipv4.prefix.len",
            (const char *)v201);
          fclose(v93);
        }
        else
        {
          puts("error");
        }
        v94 = atoi((const char *)v200);
        v95 = atoi((const char *)v201);
        ipv6_calculate_6rd_inf_ip(v211, v94, v203, v95, s1, 64, v205, 64);
        SetValue("ipv6.tun6rd.infip", s1);
        v96 = fopen("/var/ipv6_cgi_debug.log", "a+");
        v97 = v96;
        if ( v96 )
        {
          fprintf(v96, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 735, "ipv6.tun6rd.infip", s1);
          fclose(v97);
        }
        else
        {
          puts("error");
        }
        SetValue("ipv6.tun6rd.infip.prefix.len", v200);
        v98 = fopen("/var/ipv6_cgi_debug.log", "a+");
        v99 = v98;
        if ( v98 )
        {
          fprintf(
            v98,
            "%s(%d): SetValue %s = %s\n",
            "SetIPv6Wanstatus",
            736,
            "ipv6.tun6rd.infip.prefix.len",
            (const char *)v200);
          fclose(v99);
        }
        else
        {
          puts("error");
        }
        GetValue("ipv6.lan.prefix", v206);
        v100 = fopen("/var/ipv6_cgi_debug.log", "a+");
        v101 = v100;
        if ( v100 )
        {
          fprintf(v100, "%s(%d): GetValue %s = %s\n", "SetIPv6Wanstatus", 738, "ipv6.lan.prefix", v206);
          fclose(v101);
        }
        else
        {
          puts("error");
        }
        if ( !strcmp(v206, v205) )
          goto LABEL_23;
        SetValue("ipv6.lan.prefix", v205);
        v102 = fopen("/var/ipv6_cgi_debug.log", "a+");
        v103 = v102;
        if ( v102 )
        {
          fprintf(v102, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 742, "ipv6.lan.prefix", v205);
          fclose(v103);
        }
        else
        {
          puts("error");
        }
        SetValue("ipv6.lan.phy.restart", "1");
        v104 = fopen("/var/ipv6_cgi_debug.log", "a+");
        v22 = v104;
        if ( v104 )
        {
          fprintf(v104, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 743, "ipv6.lan.phy.restart", "1");
          goto LABEL_105;
        }
        goto LABEL_22;
      }
    }
    else
    {
      printf(
        "Error->%s: %s(%d)--%s(%d) Unknow connect type: %s\n",
        "/home/work/workspace/UGW6.0_P/prod/httpd/11ac/cgi/cgi_ipv6.c",
        "SetIPv6Wanstatus",
        750,
        "SetIPv6Wanstatus",
        750,
        v9);
    }
    goto LABEL_155;
  }
  v189 = parse_addr(v196, s, 128, v199, 8);
  if ( v189 )
    goto LABEL_155;
  SetValue("ipv6.wan.type", "3tun6in4");
  v48 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v49 = v48;
  if ( v48 )
  {
    fprintf(v48, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 674, "ipv6.wan.type", "3tun6in4");
    fclose(v49);
  }
  else
  {
    puts("error");
  }
  SetValue("ipv6.wan.d6c.iapd", v11);
  v50 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v51 = v50;
  if ( v50 )
  {
    fprintf(v50, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 675, "ipv6.wan.d6c.iapd", v11);
    fclose(v51);
  }
  else
  {
    puts("error");
  }
  SetValue("ipv6.tun6in4.remoteip", v12);
  v52 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v53 = v52;
  if ( v52 )
  {
    fprintf(v52, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 677, "ipv6.tun6in4.remoteip", v12);
    fclose(v53);
  }
  else
  {
    puts("error");
  }
  SetValue("ipv6.tun6in4.localip", v203);
  v54 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v55 = v54;
  if ( v54 )
  {
    fprintf(v54, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 678, "ipv6.tun6in4.localip", v203);
    fclose(v55);
  }
  else
  {
    puts("error");
  }
  SetValue("ipv6.tun6in4.itfip", s);
  v56 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v57 = v56;
  if ( v56 )
  {
    fprintf(v56, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 679, "ipv6.tun6in4.itfip", s);
    fclose(v57);
  }
  else
  {
    puts("error");
  }
  SetValue("ipv6.tun6in4.itfiplen", v199);
  v58 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v59 = v58;
  if ( v58 )
  {
    fprintf(v58, "%s(%d): SetValue %s = %s\n", "SetIPv6Wanstatus", 680, "ipv6.tun6in4.itfiplen", (const char *)v199);
    v60 = v59;
LABEL_106:
    fclose(v60);
    goto LABEL_157;
  }
LABEL_22:
  puts("error");
LABEL_23:
  v23 = 0;
LABEL_156:
  v189 = v23;
LABEL_157:
  memset(v211, 0, 0x80u);
  memset(s, 0, 0x40u);
  *(_DWORD *)v207 = 0;
  *(_DWORD *)&v207[4] = 0;
  v105 = websGetVar(wp, "IPv6En", "0");
  v106 = websGetVar(wp, "lanType", "0");
  v107 = websGetVar(wp, "prefixDelegate", "1");
  v108 = websGetVar(wp, "lanPrefix", &byte_794DF);
  v109 = websGetVar(wp, "conType", "DHCP");
  SetValue("ipv6.enable", v105);
  v110 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v111 = v110;
  if ( v110 )
  {
    fprintf(v110, "%s(%d): SetValue %s = %s\n", "SetIPv6LanStatus", 776, "ipv6.enable", v105);
    fclose(v111);
  }
  else
  {
    puts("error");
  }
  if ( !strcmp(v105, "0") )
    goto LABEL_182;
  if ( !strcmp(v106, "0") )
  {
    SetValue("ipv6.lan.type", "0dhcpv6");
    v112 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v113 = v112;
    if ( v112 )
    {
      fprintf(v112, "%s(%d): SetValue %s = %s\n", "SetIPv6LanStatus", 781, "ipv6.lan.type", "0dhcpv6");
LABEL_173:
      fclose(v113);
      goto LABEL_174;
    }
  }
  else if ( !strcmp(v106, "1") )
  {
    SetValue("ipv6.lan.type", "1slaac_sl");
    v114 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v113 = v114;
    if ( v114 )
    {
      fprintf(v114, "%s(%d): SetValue %s = %s\n", "SetIPv6LanStatus", 783, "ipv6.lan.type", "1slaac_sl");
      goto LABEL_173;
    }
  }
  else if ( !strcmp(v106, "2") )
  {
    SetValue("ipv6.lan.type", "2slaac_rdnss");
    v115 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v113 = v115;
    if ( v115 )
    {
      fprintf(v115, "%s(%d): SetValue %s = %s\n", "SetIPv6LanStatus", 785, "ipv6.lan.type", "2slaac_rdnss");
      goto LABEL_173;
    }
  }
  else
  {
    SetValue("ipv6.lan.type", "0dhcpv6");
    v116 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v113 = v116;
    if ( v116 )
    {
      fprintf(v116, "%s(%d): SetValue %s = %s\n", "SetIPv6LanStatus", 787, "ipv6.lan.type", "0dhcpv6");
      goto LABEL_173;
    }
  }
  puts("error");
LABEL_174:
  if ( !strcmp(v109, "6to4") || !strcmp(v109, "6rd") )
  {
    SetValue("ipv6.lan.prefix_auto", "0");
    v117 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v118 = v117;
    if ( v117 )
    {
      fprintf(v117, "%s(%d): SetValue %s = %s\n", "SetIPv6LanStatus", 792, "ipv6.lan.prefix_auto", "0");
      fclose(v118);
    }
    else
    {
      puts("error");
    }
    SetValue("ipv6.lan.prefix_len", "64");
    v119 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v120 = v119;
    if ( v119 )
    {
      fprintf(v119, "%s(%d): SetValue %s = %s\n", "SetIPv6LanStatus", 793, "ipv6.lan.prefix_len", "64");
      fclose(v120);
LABEL_182:
      v121 = 0;
      goto LABEL_204;
    }
LABEL_181:
    puts("error");
    goto LABEL_182;
  }
  v121 = strcmp(v107, "1");
  if ( v121 )
  {
    v121 = parse_addr(v108, v211, 128, v207, 8);
    if ( v121 )
    {
      v121 = 1;
      goto LABEL_204;
    }
    SetValue("ipv6.lan.prefix_auto", "0");
    v124 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v125 = v124;
    if ( v124 )
    {
      fprintf(v124, "%s(%d): SetValue %s = %s\n", "SetIPv6LanStatus", 809, "ipv6.lan.prefix_auto", "0");
      fclose(v125);
    }
    else
    {
      puts("error");
    }
    SetValue("ipv6.lan.prefix_len", v207);
    v126 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v127 = v126;
    if ( v126 )
    {
      fprintf(v126, "%s(%d): SetValue %s = %s\n", "SetIPv6LanStatus", 810, "ipv6.lan.prefix_len", v207);
      fclose(v127);
    }
    else
    {
      puts("error");
    }
    GetValue("ipv6.lan.prefix", s);
    v128 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v129 = v128;
    if ( v128 )
    {
      fprintf(v128, "%s(%d): GetValue %s = %s\n", "SetIPv6LanStatus", 811, "ipv6.lan.prefix", s);
      fclose(v129);
    }
    else
    {
      puts("error");
    }
    if ( !strcmp(s, v211) )
      goto LABEL_182;
    SetValue("ipv6.lan.prefix", v211);
    v130 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v131 = v130;
    if ( v130 )
    {
      fprintf(v130, "%s(%d): SetValue %s = %s\n", "SetIPv6LanStatus", 815, "ipv6.lan.prefix", v211);
      fclose(v131);
    }
    else
    {
      puts("error");
    }
    SetValue("ipv6.lan.phy.restart", "1");
    v132 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v123 = v132;
    if ( !v132 )
      goto LABEL_181;
    fprintf(v132, "%s(%d): SetValue %s = %s\n", "SetIPv6LanStatus", 816, "ipv6.lan.phy.restart", "1");
  }
  else
  {
    SetValue("ipv6.lan.prefix_auto", "1");
    v122 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v123 = v122;
    if ( !v122 )
      goto LABEL_181;
    fprintf(v122, "%s(%d): SetValue %s = %s\n", "SetIPv6LanStatus", 800, "ipv6.lan.prefix_auto", "1");
  }
  fclose(v123);
LABEL_204:
  *(_DWORD *)v202 = 0;
  *(_DWORD *)v203 = 0;
  *(_DWORD *)s1 = 0;
  *(_DWORD *)&s1[4] = 0;
  memset(v211, 0, 0x100u);
  GetValue("ipv6.enable", v202);
  v133 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v134 = v133;
  if ( v133 )
  {
    fprintf(v133, "%s(%d): GetValue %s = %s\n", "IPV6_wan_relationship_with_ipv4", 508, "ipv6.enable", v202);
    fclose(v134);
  }
  else
  {
    puts("error");
  }
  GetValue("wan1.connecttype", v203);
  v135 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v136 = v135;
  if ( v135 )
  {
    fprintf(v135, "%s(%d): GetValue %s = %s\n", "IPV6_wan_relationship_with_ipv4", 510, "wan1.connecttype", v203);
    fclose(v136);
  }
  else
  {
    puts("error");
  }
  GetValue("ipv6.wan.type", s1);
  v137 = fopen("/var/ipv6_cgi_debug.log", "a+");
  v138 = v137;
  if ( v137 )
  {
    fprintf(v137, "%s(%d): GetValue %s = %s\n", "IPV6_wan_relationship_with_ipv4", 511, "ipv6.wan.type", s1);
    fclose(v138);
  }
  else
  {
    puts("error");
  }
  if ( !strcmp(v202, "0") )
  {
    v139 = strcmp(v202, ipv6_old_flag);
    if ( v139 )
    {
      puts("send msg to netctrl NETCTRL_MODULE_IPV6, wan disconnect");
      sprintf(v211, "op=%d", 1);
      send_msg_to_netctrl(69, v211);
      v139 = strcmp("1pppoe", s1);
      if ( !v139 )
      {
        v140 = 1;
        setWanMasage(1, 1, 2);
        goto LABEL_299;
      }
    }
LABEL_215:
    v140 = 0;
    goto LABEL_299;
  }
  v139 = strcmp(s1, "6in4");
  if ( !v139 )
    goto LABEL_215;
  v139 = strcmp(s1, "6to4");
  if ( !v139 )
    goto LABEL_215;
  v139 = strcmp(s1, "6rd");
  if ( !v139 )
    goto LABEL_215;
  if ( !strcmp(s1, "0dhcp") || !strcmp(s1, "2static") )
  {
    v139 = strcmp("2", v203);
    v140 = v139;
    if ( v139 )
      goto LABEL_215;
    puts("Because ipv6 connecttype changes ipv4 connecttype to dhcp");
    SetValue("wan1.connecttype", "0");
    v141 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v142 = v141;
    if ( v141 )
    {
      fprintf(v141, "%s(%d): SetValue %s = %s\n", "set_ipv4_dhcp_configure", 185, "wan1.connecttype", "0");
      fclose(v142);
    }
    else
    {
      puts("error");
    }
    SetValue("wl.wisp.access_mode", "dhcp");
    v143 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v144 = v143;
    if ( v143 )
    {
      fprintf(v143, "%s(%d): SetValue %s = %s\n", "set_ipv4_dhcp_configure", 186, "wl.wisp.access_mode", "dhcp");
      fclose(v144);
    }
    else
    {
      puts("error");
    }
    SetValue("wl.wisp.ip", &byte_794DF);
    v145 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v146 = v145;
    if ( v145 )
    {
      fprintf(v145, "%s(%d): SetValue %s = %s\n", "set_ipv4_dhcp_configure", 187, "wl.wisp.ip", &byte_794DF);
      fclose(v146);
    }
    else
    {
      puts("error");
    }
    SetValue("wl.wisp.mask", &byte_794DF);
    v147 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v148 = v147;
    if ( v147 )
    {
      fprintf(v147, "%s(%d): SetValue %s = %s\n", "set_ipv4_dhcp_configure", 188, "wl.wisp.mask", &byte_794DF);
      fclose(v148);
    }
    else
    {
      puts("error");
    }
    SetValue("wl.wisp.gateway", &byte_794DF);
    v149 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v150 = v149;
    if ( v149 )
    {
      fprintf(v149, "%s(%d): SetValue %s = %s\n", "set_ipv4_dhcp_configure", 189, "wl.wisp.gateway", &byte_794DF);
      fclose(v150);
    }
    else
    {
      puts("error");
    }
    SetValue("wl.wisp.dns1", &byte_794DF);
    v151 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v152 = v151;
    if ( v151 )
    {
      fprintf(v151, "%s(%d): SetValue %s = %s\n", "set_ipv4_dhcp_configure", 190, "wl.wisp.dns1", &byte_794DF);
      fclose(v152);
    }
    else
    {
      puts("error");
    }
    SetValue("wl.wisp.dns2", &byte_794DF);
    v153 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v154 = v153;
    if ( v153 )
    {
      fprintf(v153, "%s(%d): SetValue %s = %s\n", "set_ipv4_dhcp_configure", 191, "wl.wisp.dns2", &byte_794DF);
      fclose(v154);
    }
    else
    {
      puts("error");
    }
    SetValue("wan1.ppoe.double.access", "0");
    v155 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v156 = v155;
    if ( v155 )
    {
      fprintf(v155, "%s(%d): SetValue %s = %s\n", "set_ipv4_dhcp_configure", 193, "wan1.ppoe.double.access", "0");
      fclose(v156);
    }
    else
    {
      puts("error");
    }
    reset_wan_status();
    v157 = 0;
  }
  else
  {
    v139 = strcmp("1pppoe", s1);
    v140 = v139;
    if ( v139 )
      goto LABEL_215;
    puts("Because ipv6 connecttype changes ipv4 connecttype to pppoe");
    memset(v205, 0, 0x20u);
    memset(v206, 0, 0x20u);
    memset(v207, 0, 0x20u);
    memset(s, 0, 0x20u);
    GetValue("ipv6.wan.pppoe.username", v207);
    v158 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v159 = v158;
    if ( v158 )
    {
      fprintf(v158, "%s(%d): GetValue %s = %s\n", "set_ipv4_pppoe_configure", 138, "ipv6.wan.pppoe.username", v207);
      fclose(v159);
    }
    else
    {
      puts("error");
    }
    GetValue("ipv6.wan.pppoe.password", s);
    v160 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v161 = v160;
    if ( v160 )
    {
      fprintf(v160, "%s(%d): GetValue %s = %s\n", "set_ipv4_pppoe_configure", 139, "ipv6.wan.pppoe.password", s);
      fclose(v161);
    }
    else
    {
      puts("error");
    }
    GetValue("wan1.ppoe.userid", v205);
    v162 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v163 = v162;
    if ( v162 )
    {
      fprintf(v162, "%s(%d): GetValue %s = %s\n", "set_ipv4_pppoe_configure", 140, "wan1.ppoe.userid", v205);
      fclose(v163);
    }
    else
    {
      puts("error");
    }
    GetValue("wan1.ppoe.pwd", v206);
    v164 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v165 = v164;
    if ( v164 )
    {
      fprintf(v164, "%s(%d): GetValue %s = %s\n", "set_ipv4_pppoe_configure", 141, "wan1.ppoe.pwd", v206);
      fclose(v165);
    }
    else
    {
      puts("error");
    }
    if ( strncmp(v207, v205, 0x20u) || strncmp(s, v206, 0x20u) )
    {
      SetValue("wan1.pppoe.auth.changed", "1");
      v166 = fopen("/var/ipv6_cgi_debug.log", "a+");
      v167 = v166;
      if ( v166 )
      {
        fprintf(v166, "%s(%d): SetValue %s = %s\n", "set_ipv4_pppoe_configure", 150, "wan1.pppoe.auth.changed", "1");
        fclose(v167);
      }
      else
      {
        puts("error");
      }
      SetValue("wan1.ppoe.userid", v207);
      v168 = fopen("/var/ipv6_cgi_debug.log", "a+");
      v169 = v168;
      if ( v168 )
      {
        fprintf(v168, "%s(%d): SetValue %s = %s\n", "set_ipv4_pppoe_configure", 151, "wan1.ppoe.userid", v207);
        fclose(v169);
      }
      else
      {
        puts("error");
      }
      SetValue("wan1.ppoe.pwd", s);
      v170 = fopen("/var/ipv6_cgi_debug.log", "a+");
      v171 = v170;
      if ( v170 )
      {
        fprintf(v170, "%s(%d): SetValue %s = %s\n", "set_ipv4_pppoe_configure", 152, "wan1.ppoe.pwd", s);
        fclose(v171);
      }
      else
      {
        puts("error");
      }
    }
    SetValue("wan1.connecttype", "2");
    v172 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v173 = v172;
    if ( v172 )
    {
      fprintf(v172, "%s(%d): SetValue %s = %s\n", "set_ipv4_pppoe_configure", 155, "wan1.connecttype", "2");
      fclose(v173);
    }
    else
    {
      puts("error");
    }
    SetValue("wl.wisp.access_mode", "pppoe");
    v174 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v175 = v174;
    if ( v174 )
    {
      fprintf(v174, "%s(%d): SetValue %s = %s\n", "set_ipv4_pppoe_configure", 156, "wl.wisp.access_mode", "pppoe");
      fclose(v175);
    }
    else
    {
      puts("error");
    }
    SetValue("wl.wisp.ip", &byte_794DF);
    v176 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v177 = v176;
    if ( v176 )
    {
      fprintf(v176, "%s(%d): SetValue %s = %s\n", "set_ipv4_pppoe_configure", 157, "wl.wisp.ip", &byte_794DF);
      fclose(v177);
    }
    else
    {
      puts("error");
    }
    SetValue("wl.wisp.mask", &byte_794DF);
    v178 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v179 = v178;
    if ( v178 )
    {
      fprintf(v178, "%s(%d): SetValue %s = %s\n", "set_ipv4_pppoe_configure", 158, "wl.wisp.mask", &byte_794DF);
      fclose(v179);
    }
    else
    {
      puts("error");
    }
    SetValue("wl.wisp.gateway", &byte_794DF);
    v180 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v181 = v180;
    if ( v180 )
    {
      fprintf(v180, "%s(%d): SetValue %s = %s\n", "set_ipv4_pppoe_configure", 159, "wl.wisp.gateway", &byte_794DF);
      fclose(v181);
    }
    else
    {
      puts("error");
    }
    SetValue("wl.wisp.dns1", &byte_794DF);
    v182 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v183 = v182;
    if ( v182 )
    {
      fprintf(v182, "%s(%d): SetValue %s = %s\n", "set_ipv4_pppoe_configure", 160, "wl.wisp.dns1", &byte_794DF);
      fclose(v183);
    }
    else
    {
      puts("error");
    }
    SetValue("wl.wisp.dns2", &byte_794DF);
    v184 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v185 = v184;
    if ( v184 )
    {
      fprintf(v184, "%s(%d): SetValue %s = %s\n", "set_ipv4_pppoe_configure", 161, "wl.wisp.dns2", &byte_794DF);
      fclose(v185);
    }
    else
    {
      puts("error");
    }
    SetValue("wan1.ppoe.double.access", "0");
    v186 = fopen("/var/ipv6_cgi_debug.log", "a+");
    v187 = v186;
    if ( v186 )
    {
      fprintf(v186, "%s(%d): SetValue %s = %s\n", "set_ipv4_pppoe_configure", 163, "wan1.ppoe.double.access", "0");
      fclose(v187);
    }
    else
    {
      puts("error");
    }
    reset_wan_status();
    snprintf(v211, 0x100u, "op=%d", 1);
    send_msg_to_netctrl(69, v211);
    v157 = 2;
  }
  setWanMasage(1, 1, v157);
LABEL_299:
  if ( v121 | v189 )
  {
LABEL_305:
    v188 = 1;
    goto error_0;
  }
  if ( !CommitCfm(v139) )
  {
    printf(
      "Error->%s: %s(%d)--%s(%d) cfm commit error!\n",
      "/home/work/workspace/UGW6.0_P/prod/httpd/11ac/cgi/cgi_ipv6.c",
      "formSetIPv6status",
      847,
      "formSetIPv6status",
      847);
    goto LABEL_305;
  }
  if ( !v140 )
  {
    puts("send msg to netctrl NETCTRL_MODULE_IPV6, wan config change");
    sprintf(param_str, "op=%d", 5);
    send_msg_to_netctrl(69, param_str);
  }
  puts("send msg to netctrl, restart ipv6 lan service");
  memset(param_str, 0, sizeof(param_str));
  sprintf(param_str, "op=%d", 11);
  send_msg_to_netctrl(70, param_str);
  v188 = 0;
error_0:
  printf("error code: %d\n", v188);
  snprintf(buf, 0x100u, "{\"errCode\":%d}", v188);
  websTransfer(wp, buf);
}
