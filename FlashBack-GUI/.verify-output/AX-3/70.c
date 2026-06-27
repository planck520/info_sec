/* =====================================================
 *  Path 70
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - formWanInfoSet (arg=1, call_ea=0x30858, func_ea=0x30290, label=needs_check)
 *        call: LABEL_55:
 *    - formSetPPTPClient (arg=1, call_ea=0x4a52c, func_ea=0x4a210, label=needs_check)
 *        call: SetValue("vpn.cli.pptpEnable", Var);
 *    - websGetVar (arg=ret, call_ea=0x4a254, func_ea=source, label=source)
 *        call: Var = websGetVar(wp, "clientEn", "0");
 * ===================================================== */


/* Function: formWanInfoSet @ 0x30290 */
int __fastcall formWanInfoSet(webs_t wp, int wan_id)
{
  char_t *v2; // r5
  char_t *Var; // r0
  const char *v6; // r6
  char_t *v7; // r1
  int v8; // r6
  UGW_WAN_CONNECT_TYPE_ENUM v9; // r8
  _BOOL4 v10; // r0
  char *v11; // r2
  int v12; // r0
  int v13; // r0
  int result; // r0
  void *v15; // r0
  const char *wifi_workmode; // r0
  int WanConnType; // r0
  char pptpclient[4]; // [sp+8h] [bp-18h] BYREF
  char l2tpclient[4]; // [sp+Ch] [bp-14h] BYREF
  char wans_flag[16]; // [sp+10h] [bp-10h] BYREF
  char mib_name[256]; // [sp+20h] [bp+0h] BYREF
  char s[260]; // [sp+120h] [bp+100h] BYREF

  v2 = 0;
  *(_DWORD *)pptpclient = 0;
  *(_DWORD *)l2tpclient = 0;
  memset(wans_flag, 0, sizeof(wans_flag));
  memset(mib_name, 0, sizeof(mib_name));
  Var = websGetVar(wp, "action", "connect");
  v6 = Var;
  if ( wan_id == 1 )
  {
    v7 = "wanType";
    goto LABEL_5;
  }
  if ( wan_id == 2 )
  {
    v7 = "wanType2";
LABEL_5:
    v2 = websGetVar(wp, v7, "0");
    if ( !v6 )
    {
      printf("wan_action is null %s\n", "exchange_wan_action");
      if ( v2 )
      {
        v8 = -1;
        goto LABEL_11;
      }
LABEL_55:
      GetValue("vpn.cli.pptpEnable", pptpclient);
      GetValue("vpn.cli.l2tpEnable", l2tpclient);
      GetValue("wans.flag", wans_flag);
      return 1;
    }
    goto LABEL_9;
  }
  if ( !Var )
  {
    printf("wan_action is null %s\n", "exchange_wan_action");
    goto LABEL_55;
  }
LABEL_9:
  if ( !strncmp("connect", v6, 7u) )
  {
    if ( !v2 )
    {
      v9 = UGW_WAN_CONNECT_TYPE::UGW_WAN_CONNECT_DHCP;
      GetValue("vpn.cli.pptpEnable", pptpclient);
      GetValue("vpn.cli.l2tpEnable", l2tpclient);
      GetValue("wans.flag", wans_flag);
      goto LABEL_14;
    }
    v8 = 1;
    goto LABEL_11;
  }
  v8 = -(strncmp("disconnect", v6, 0xAu) != 0);
  if ( v2 )
  {
LABEL_11:
    v9 = atoi(v2);
    goto LABEL_13;
  }
  v9 = UGW_WAN_CONNECT_TYPE::UGW_WAN_CONNECT_DHCP;
LABEL_13:
  GetValue("vpn.cli.pptpEnable", pptpclient);
  GetValue("vpn.cli.l2tpEnable", l2tpclient);
  GetValue("wans.flag", wans_flag);
  if ( v8 != 1 )
  {
    if ( !v8 )
    {
      wisp_set_webpage_status(0);
      memset(mib_name, 0, sizeof(mib_name));
      sprintf(mib_name, "wan%d_action_flag", wan_id);
      SetValue(mib_name, "0");
      doSystemCmd("echo \"0 0\" > /etc/conntime%d", wan_id);
      WanConnType = getWanConnType(wan_id);
      setWanMasage(0, wan_id, WanConnType);
      doSystemCmd("rm -rf /etc/ppp/pppoe_auth_status.wan%d &", wan_id);
      doSystemCmd("rm -fr /etc/ppp/wan%d_ppoe_auth_code", wan_id);
      return 0;
    }
    return 1;
  }
LABEL_14:
  memset(s, 0, 0x100u);
  GetValue("wan1.connecttype", s);
  v10 = !s[0] || atoi(s) == v9;
  wisp_set_webpage_status(v10);
  if ( v9 )
  {
    if ( v9 == UGW_WAN_CONNECT_TYPE::UGW_WAN_CONNECT_STATIC )
    {
      setWanValue(wan_id, "connecttype", v2);
      setStaticConfig(wp, wan_id);
    }
    else if ( v9 == UGW_WAN_CONNECT_TYPE::UGW_WAN_CONNECT_PPPOE )
    {
      setWanValue(wan_id, "connecttype", v2);
      setPppoeConfig(wp, wan_id);
    }
  }
  else
  {
    setWanValue(wan_id, "connecttype", v2);
    setDhcpConfig(wp, wan_id);
  }
  if ( v2 )
  {
    if ( wan_id == 1 )
    {
      switch ( v9 )
      {
        case UGW_WAN_CONNECT_TYPE::UGW_WAN_CONNECT_PPPOE_DOUBLE:
          setWanValue(1, "connecttype", v2);
          setDoublePppoeConfig(wp, 1);
          break;
        case UGW_WAN_CONNECT_TYPE::UGW_WAN_CONNECT_PPTP:
          setWanValue(1, "connecttype", v2);
          setDoublePptpConfig(wp, 1);
          break;
        case UGW_WAN_CONNECT_TYPE::UGW_WAN_CONNECT_L2TP:
          setWanValue(1, "connecttype", v2);
          setDoubleL2tpConfig(wp, 1);
          break;
        default:
          goto LABEL_52;
      }
      set_double_connect_ipv6_shutdown();
LABEL_52:
      v11 = websGetVar(wp, "downSpeedLimit", &byte_794DF);
      v12 = 1;
      goto LABEL_36;
    }
  }
  else if ( wan_id == 1 )
  {
    goto LABEL_52;
  }
  if ( wan_id != 2 )
    goto LABEL_37;
  v11 = websGetVar(wp, "downSpeedLimit2", &byte_794DF);
  v12 = 2;
LABEL_36:
  setWanValue(v12, "downrate", v11);
LABEL_37:
  doSystemCmd("rm -rf /etc/ppp/pppoe_auth_status.wan%d &", wan_id);
  doSystemCmd("rm -fr /etc/ppp/wan%d_ppoe_auth_code", wan_id);
  if ( set_ipv6_configure(v9) == 1 )
    send_message_ipv6_changed();
  memset(mib_name, 0, sizeof(mib_name));
  sprintf(mib_name, "wan%d_isonln", wan_id);
  SetValue(mib_name, "0");
  memset(mib_name, 0, sizeof(mib_name));
  sprintf(mib_name, "wan%d_check", wan_id);
  SetValue(mib_name, "0");
  memset(mib_name, 0, sizeof(mib_name));
  sprintf(mib_name, "wan%d_err_check", wan_id);
  SetValue(mib_name, "0");
  memset(mib_name, 0, sizeof(mib_name));
  sprintf(mib_name, "wan%d_action_flag", wan_id);
  SetValue(mib_name, "1");
  v13 = doSystemCmd("echo \"0 0\" > /etc/conntime%d", wan_id);
  result = CommitCfm(v13);
  if ( result )
  {
    if ( (unsigned int)(v9 - 3) <= 1 )
    {
      v15 = memset(s, 0, 0x100u);
      wifi_workmode = (const char *)get_wifi_workmode(v15);
      if ( !strcmp("wisp", wifi_workmode) )
        sprintf(s, "op=%d,wan_id=%d", 14, 5);
      else
        sprintf(s, "op=%d,wan_id=%d", 14, wan_id);
      if ( !strcmp(pptpclient, "1") )
        send_msg_to_netctrl(22, s);
      if ( !strcmp(l2tpclient, "1") )
        send_msg_to_netctrl(23, s);
    }
    setWanMasage(1, wan_id, v9);
    return 0;
  }
  return result;
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
