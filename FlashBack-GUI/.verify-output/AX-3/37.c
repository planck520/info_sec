/* =====================================================
 *  Path 37
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = websGetVar
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - fromAdvSetMacMtuWan (arg=1, call_ea=0x32888, func_ea=0x325e0, label=needs_check)
 *        call: strcpy(dest, v17);
 *    - websGetVar (arg=ret, call_ea=0x3287c, func_ea=source, label=source)
 *        call: v17 = websGetVar(wp, v11, &byte_794DF);
 * ===================================================== */


/* Function: fromAdvSetMacMtuWan @ 0x325E0 */
void __fastcall fromAdvSetMacMtuWan(webs_t wp, char_t *path, char_t *query)
{
  char *mac; // r5
  int v4; // r4
  int v5; // r10
  char_t *Var; // r0
  char_t *v7; // r0
  char_t *v8; // r0
  char_t *v9; // r0
  char_t *v10; // r0
  char_t *v11; // r1
  char_t *v12; // r0
  char_t *v13; // r0
  char_t *v14; // r0
  char_t *v15; // r0
  char_t *v16; // r0
  char_t *v17; // r0
  _BOOL4 v18; // r8
  bool v19; // zf
  const char *v20; // r1
  int v21; // r0
  bool v22; // zf
  int v23; // r9
  char *v24; // r1
  const char *v25; // r0
  int v26; // r8
  int v27; // r6
  char *v28; // r9
  int v29; // r0
  char *v30; // r1
  int v31; // r0
  int v32; // r0
  int v33; // r0
  int wifi_extern_mode; // r0
  char *dest; // [sp+Ch] [bp-7C8h]
  int wann; // [sp+14h] [bp-7C0h]
  int v38; // [sp+1Ch] [bp-7B8h]
  int v39; // [sp+34h] [bp-7A0h] BYREF
  int v40; // [sp+38h] [bp-79Ch] BYREF
  char mib_value[16]; // [sp+3Ch] [bp-798h] BYREF
  char s1[16]; // [sp+4Ch] [bp-788h] BYREF
  char s[32]; // [sp+5Ch] [bp-778h] BYREF
  char v44[32]; // [sp+7Ch] [bp-758h] BYREF
  char ret_buf[64]; // [sp+9Ch] [bp-738h] BYREF
  char v46[256]; // [sp+DCh] [bp-6F8h] BYREF
  char v47[256]; // [sp+1DCh] [bp-5F8h] BYREF
  WAN_ARGUMENT wan_set_param[2]; // [sp+2DCh] [bp-4F8h] BYREF

  memset(mib_value, 0, sizeof(mib_value));
  memset(ret_buf, 0, sizeof(ret_buf));
  mac = wan_set_param[0].mac;
  memset(wan_set_param, 0, sizeof(wan_set_param));
  GetValue("wans.flag", mib_value);
  v4 = 0;
  v38 = atoi(mib_value);
  wann = 0;
  while ( v4 < v38 )
  {
    memset(s, 0, sizeof(s));
    ++v4;
    memset(v46, 0, sizeof(v46));
    sprintf(s, "wan%d.connecttype", v4);
    GetValue(s, mac - 84);
    v5 = atoi(mac - 84);
    dest = mac + 274;
    if ( v4 == 1 )
    {
      Var = websGetVar(wp, "wanMTU", &byte_794DF);
      strcpy(mac - 68, Var);
      v7 = websGetVar(wp, "wanSpeed", "0");
      strcpy(mac - 60, v7);
      v8 = websGetVar(wp, "cloneType", "0");
      strcpy(mac - 44, v8);
      v9 = websGetVar(wp, "mac", &byte_794DF);
      strcpy(mac, v9);
      v10 = websGetVar(wp, "serviceName", &byte_794DF);
      strcpy(mac + 18, v10);
      v11 = "serverName";
    }
    else
    {
      v12 = websGetVar(wp, "wanMTU2", &byte_794DF);
      strcpy(mac - 68, v12);
      v13 = websGetVar(wp, "wanSpeed2", "0");
      strcpy(mac - 60, v13);
      v14 = websGetVar(wp, "cloneType2", "0");
      strcpy(mac - 44, v14);
      v15 = websGetVar(wp, "mac2", &byte_794DF);
      strcpy(mac, v15);
      v16 = websGetVar(wp, "serviceName2", &byte_794DF);
      strcpy(mac + 18, v16);
      v11 = "serverName2";
    }
    v17 = websGetVar(wp, v11, &byte_794DF);
    strcpy(dest, v17);
    memset(v44, 0, sizeof(v44));
    memset(v47, 0, sizeof(v47));
    switch ( v5 )
    {
      case 0:
        memset(v44, 0, sizeof(v44));
        memset(v47, 0, sizeof(v47));
        sprintf(v44, "wan%d.dynamicMTU", v4);
        goto LABEL_13;
      case 1:
        memset(v44, 0, sizeof(v44));
        memset(v47, 0, sizeof(v47));
        sprintf(v44, "wan%d.staticMTU", v4);
        goto LABEL_13;
      case 2:
      case 5:
        memset(v44, 0, sizeof(v44));
        memset(v47, 0, sizeof(v47));
        sprintf(v44, "wan%d.ppoe.mtu", v4);
        goto LABEL_13;
      case 3:
        memset(v44, 0, sizeof(v44));
        memset(v47, 0, sizeof(v47));
        sprintf(v44, "wan%d.pptp.mtu", v4);
        goto LABEL_13;
      case 4:
        memset(v44, 0, sizeof(v44));
        memset(v47, 0, sizeof(v47));
        sprintf(v44, "wan%d.l2tp.mtu", v4);
LABEL_13:
        GetValue(v44, v47);
        break;
      default:
        break;
    }
    v18 = strncmp(v47, mac - 68, 0x100u) != 0;
    v19 = v5 == 5;
    if ( v5 != 5 )
      v19 = v5 == 2;
    if ( v19 )
    {
      memset(s, 0, sizeof(s));
      memset(v46, 0, sizeof(v46));
      sprintf(s, "wan%d.ppoe.sev", v4);
      GetValue(s, v46);
      if ( strncmp(v46, mac + 18, 0x100u) )
        v18 = 1;
      memset(s, 0, sizeof(s));
      memset(v46, 0, sizeof(v46));
      sprintf(s, "wan%d.ppoe.ac", v4);
      GetValue(s, v46);
      if ( strncmp(v46, dest, 0x100u) )
        v18 = 1;
    }
    memset(s, 0, sizeof(s));
    memset(v46, 0, sizeof(v46));
    sprintf(s, "wan%d.param", v4);
    GetValue(s, v46);
    if ( strncmp(v46, mac - 60, 0x100u) )
      v18 = 1;
    memset(v47, 0, sizeof(v47));
    memset(s1, 0, sizeof(s1));
    memset(v44, 0, sizeof(v44));
    sprintf(v44, "wan%d.mac.clone.type", v4);
    GetValue(v44, s1);
    if ( strncmp(s1, mac - 44, 0x10u) )
      v18 = 1;
    if ( !strncmp(s1, "1", 0x10u) )
    {
      get_ip_from_mac(wp->ipaddr, mac - 18);
      memset(v44, 0, sizeof(v44));
      memset(v47, 0, sizeof(v47));
      sprintf(v44, "wan%d.macaddr", v4);
      GetValue(v44, v47);
      v20 = mac - 18;
      goto LABEL_30;
    }
    if ( !strncmp(s1, "2", 0x10u) )
    {
      memset(v44, 0, sizeof(v44));
      memset(v47, 0, sizeof(v47));
      sprintf(v44, "wan%d.macaddr", v4);
      GetValue(v44, v47);
      v20 = mac;
LABEL_30:
      if ( strncmp(v47, v20, 0x100u) )
        goto LABEL_32;
    }
    if ( !v18 )
      goto LABEL_79;
LABEL_32:
    memset(v47, 0, sizeof(v47));
    memset(s, 0, 0x10u);
    memset(v44, 0, sizeof(v44));
    v39 = 0;
    *(_DWORD *)s1 = 0;
    v40 = 0;
    GetValue("vpn.cli.l2tpEnable", s1);
    GetValue("vpn.cli.pptpEnable", &v40);
    GetValue("vpn.ser.pptpdEnable", &v39);
    memset(v46, 0, 0x20u);
    v21 = atoi(mac - 84);
    v22 = v21 == 5;
    if ( v21 != 5 )
      v22 = v21 == 2;
    v23 = v21;
    if ( v22 )
    {
      memset(v46, 0, 0x20u);
      sprintf(v46, "wan%d.ppoe.sev", v4);
      SetValue(v46, mac + 18);
      memset(v46, 0, 0x20u);
      sprintf(v46, "wan%d.ppoe.ac", v4);
      SetValue(v46, dest);
    }
    switch ( v23 )
    {
      case 0:
        memset(v46, 0, 0x20u);
        sprintf(v46, "wan%d.dynamicMTU", v4);
        SetValue(v46, mac - 68);
        if ( v4 != 1 )
          goto LABEL_49;
        v24 = mac - 68;
        v25 = "wl.wisp.mtu";
        goto LABEL_48;
      case 1:
        memset(v46, 0, 0x20u);
        sprintf(v46, "wan%d.staticMTU", v4);
        SetValue(v46, mac - 68);
        if ( v4 != 1 )
          goto LABEL_49;
        v24 = mac - 68;
        v25 = "wl.wisp.mtu";
        goto LABEL_48;
      case 2:
        memset(v46, 0, 0x20u);
        sprintf(v46, "wan%d.ppoe.mtu", v4);
        SetValue(v46, mac - 68);
        if ( v4 != 1 )
          goto LABEL_49;
        v24 = mac - 68;
        v25 = "wl.wisp.pppoe_mtu";
        goto LABEL_48;
      case 3:
        memset(v46, 0, 0x20u);
        sprintf(v46, "wan%d.pptp.mtu", v4);
        goto LABEL_47;
      case 4:
        memset(v46, 0, 0x20u);
        sprintf(v46, "wan%d.l2tp.mtu", v4);
        goto LABEL_47;
      case 5:
        memset(v46, 0, 0x20u);
        sprintf(v46, "wan%d.ppoe.mtu", v4);
LABEL_47:
        v24 = mac - 68;
        v25 = v46;
LABEL_48:
        SetValue(v25, v24);
LABEL_49:
        v26 = 0;
        break;
      default:
        v26 = 1;
        break;
    }
    memset(v44, 0, sizeof(v44));
    sprintf(v44, "wan%d.param", v4);
    SetValue(v44, mac - 60);
    memset(v46, 0, 0x20u);
    v27 = strcmp(mac - 44, "0");
    if ( !v27 )
    {
      v28 = mac - 36;
      memset(v46, 0, 0x20u);
      sprintf(v46, "wan%d.macaddr", v4);
      get_wan_fact_mac(v4, mac - 36);
      goto LABEL_57;
    }
    v29 = strcmp(mac - 44, "1");
    v27 = v29;
    if ( !v29 )
    {
      v28 = mac - 18;
      get_ip_from_mac(wp->ipaddr, mac - 18);
      memset(v46, 0, 0x20u);
      sprintf(v46, "wan%d.macaddr", v4);
LABEL_57:
      v30 = v28;
LABEL_61:
      SetValue(v46, v30);
      goto LABEL_62;
    }
    v31 = strcmp(mac - 44, "2");
    v27 = v31;
    if ( !v31 )
    {
      memset(v46, 0, 0x20u);
      sprintf(v46, "wan%d.macaddr", v4);
      v30 = mac;
      goto LABEL_61;
    }
    v27 = 1;
LABEL_62:
    memset(v46, 0, 0x20u);
    sprintf(v46, "wan%d.mac.clone.type", v4);
    v32 = SetValue(v46, mac - 44);
    wann = v27 | v26;
    if ( v27 | v26 || !CommitCfm(v32) )
    {
      puts("formWanArgumentSet error!");
      wann = 1;
      goto LABEL_79;
    }
    if ( !strcmp((const char *)&v39, "1") )
    {
      sprintf(v47, "op=%d,wan_id=%d", 14, v4);
      send_msg_to_netctrl(20, v47);
    }
    if ( !strcmp((const char *)&v40, "1") )
    {
      sprintf(v47, "op=%d,wan_id=%d", 14, v4);
      send_msg_to_netctrl(22, v47);
    }
    if ( !strcmp(s1, "1") )
    {
      sprintf(v47, "op=%d,wan_id=%d", 14, v4);
      send_msg_to_netctrl(23, v47);
    }
    sprintf(v47, "op=%d,wan_id=%d", 11, v4);
    send_msg_to_netctrl(2, v47);
    sprintf(v47, "op=%d", 9);
    v33 = send_msg_to_netctrl(27, v47);
    wifi_extern_mode = get_wifi_extern_mode(v33);
    if ( wifi_extern_mode == 1 )
    {
      sprintf(v47, "op=%d,wl_rate=%d,index=1", 3, 2);
LABEL_74:
      send_msg_to_netctrl(19, v47);
      goto LABEL_75;
    }
    if ( wifi_extern_mode == 3 )
    {
      sprintf(v47, "op=%d,wl_rate=%d,index=1", 3, 5);
      goto LABEL_74;
    }
LABEL_75:
    GetValue("ipv6.wan.type", s);
    if ( !strcmp(s, "0dhcp") || !strcmp(s, "2static") )
    {
      puts("send msg to netctrl, wan config change");
      snprintf(v47, 0x100u, "op=%d", 5);
      send_msg_to_netctrl(69, v47);
    }
LABEL_79:
    mac += 616;
  }
  sprintf(ret_buf, "{\"errCode\":%d}", wann);
  websTransfer(wp, ret_buf);
}
