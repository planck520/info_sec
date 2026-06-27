/* =====================================================
 *  Path 53
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - formSetPPTPClient (arg=1, call_ea=0x4a2d4, func_ea=0x4a210, label=certain)
 *        call: GetValue("vpn.ser.pptpdEnable", param_str);
 *    - formSetPPTPServer (arg=1, call_ea=0x48cd0, func_ea=0x48bac, label=certain)
 *        call: SetValue("vpn.ser.pptpdEnable", Var);
 *    - websGetVar (arg=ret, call_ea=0x48cc0, func_ea=source, label=source)
 *        call: Var = websGetVar(wp, "serverEn", "1");
 * ===================================================== */


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


/* Function: formSetPPTPServer @ 0x48BAC */
void __fastcall formSetPPTPServer(webs_t wp, char_t *path, char_t *query)
{
  int mibname; // r0
  int v5; // r0
  char_t *Var; // r7
  int v7; // r0
  char *v8; // r1
  char_t *v9; // r9
  char_t *v10; // r0
  int v11; // r0
  char_t *fmt; // [sp+0h] [bp-3A0h]
  char_t *fmta; // [sp+0h] [bp-3A0h]
  char_t *v14; // [sp+Ch] [bp-394h]
  char_t *v15; // [sp+18h] [bp-388h]
  char_t *v16; // [sp+1Ch] [bp-384h]
  char client_pptp_enable[4]; // [sp+30h] [bp-370h] BYREF
  char client_l2tp_enable[4]; // [sp+34h] [bp-36Ch] BYREF
  char wlan0_work_mode[16]; // [sp+38h] [bp-368h] BYREF
  char wlan1_work_mode[16]; // [sp+48h] [bp-358h] BYREF
  char v21[16]; // [sp+58h] [bp-348h] BYREF
  _BYTE v22[16]; // [sp+68h] [bp-338h] BYREF
  char v23[8]; // [sp+78h] [bp-328h] BYREF
  char v24[8]; // [sp+80h] [bp-320h] BYREF
  char v25[40]; // [sp+88h] [bp-318h] BYREF
  char v26[8]; // [sp+B0h] [bp-2F0h] BYREF
  char v27[64]; // [sp+B8h] [bp-2E8h] BYREF
  char s[128]; // [sp+F8h] [bp-2A8h] BYREF
  char mib_name[256]; // [sp+178h] [bp-228h] BYREF
  char param_str[256]; // [sp+278h] [bp-128h] BYREF

  memset(wlan0_work_mode, 0, sizeof(wlan0_work_mode));
  memset(wlan1_work_mode, 0, sizeof(wlan1_work_mode));
  *(_DWORD *)client_pptp_enable = 0;
  *(_DWORD *)client_l2tp_enable = 0;
  memset(mib_name, 0, sizeof(mib_name));
  mibname = wifi_get_mibname("wlan0", "workmode", mib_name);
  GetValue(mibname, wlan0_work_mode);
  v5 = wifi_get_mibname("wlan1", "workmode", mib_name);
  GetValue(v5, wlan1_work_mode);
  GetValue("vpn.cli.pptpEnable", client_pptp_enable);
  GetValue("vpn.cli.l2tpEnable", client_l2tp_enable);
  if ( !strcmp(wlan0_work_mode, "apclient") || !strcmp(wlan1_work_mode, "apclient") )
    goto finish;
  Var = websGetVar(wp, "serverEn", "1");
  SetValue("vpn.ser.pptpdEnable", Var);
  if ( strcmp(Var, "0") )
  {
    if ( strcmp(Var, "1") )
      goto finish;
    memset(s, 0, sizeof(s));
    memset(v27, 0, sizeof(v27));
    memset(param_str, 0, 0x80u);
    memset(v21, 0, sizeof(v21));
    memset(v22, 0, sizeof(v22));
    v15 = websGetVar(wp, "mppe", "1");
    v16 = websGetVar(wp, "mppeOp", "128");
    v9 = websGetVar(wp, "startIp", &byte_794DF);
    v10 = websGetVar(wp, "endIp", &byte_794DF);
    v14 = v10;
    if ( !*v9
      || !*v10
      || _isoc99_sscanf(v9, "%[^.].%[^.].%[^.].%s", v23, v24, v25, &v25[8]) != 4
      || _isoc99_sscanf(v14, "%[^.].%[^.].%[^.].%s", &v25[16], &v25[24], &v25[32], v26) != 4 )
    {
      goto finish;
    }
    sprintf(s, "%s.%s.%s.%s", v23, v24, v25, "0");
    sprintf(v27, "%s.%s.%s.%s", v23, v24, v25, "1");
    sprintf(param_str, "%s-%s", v9, v26);
    if ( get_systerm_mode(v22) == 2 )
      sprintf(v21, "%d", 5);
    else
      sprintf(v21, "%d", 1);
    SetValue("vpn.ser.pptpwanid", v21);
    SetValue("vpn.ser.pptpdmppe", v15);
    SetValue("vpn.ser.pptpdmppe.op", v16);
    SetValue("vpn.ser.pptpdnetseg", s);
    SetValue("vpn.ser.pptpserver", v27);
    SetValue("vpn.ser.pptpipcli", param_str);
    v11 = guest_ip_conflict_handle(v27, "255.255.255.0", 5);
    enable_gro(v11);
    v8 = "1";
    goto LABEL_17;
  }
  v7 = strcmp(client_pptp_enable, "0");
  if ( !v7 )
  {
    v7 = strcmp(client_l2tp_enable, "0");
    if ( !v7 )
    {
      v8 = "0";
LABEL_17:
      v7 = SetValue("inet_gro_disable", v8);
    }
  }
  if ( CommitCfm(v7) )
  {
    memset(param_str, 0, sizeof(param_str));
    sprintf(param_str, "op=%d", 3);
    send_msg_to_netctrl(20, param_str);
    sprintf(param_str, "advance_type=%d", 1);
    send_msg_to_netctrl(5, param_str);
  }
finish:
  websWrite(wp, fmt);
  websWrite(wp, fmta);
  websDone(wp, 200);
}
