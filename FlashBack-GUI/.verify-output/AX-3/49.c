/* =====================================================
 *  Path 49
 *  vuln_type = CWE-120
 *  sink_func = sprintf
 *  source_func = websGetVar
 *  Hops:
 *    - sprintf (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - formSetPPTPServer (arg=2, call_ea=0x48ef4, func_ea=0x48bac, label=needs_check)
 *        call: sprintf(param_str, "%s-%s", v9, v26);
 *    - websGetVar (arg=ret, call_ea=0x48dfc, func_ea=source, label=source)
 *        call: v9 = websGetVar(wp, "startIp", &byte_794DF);
 * ===================================================== */


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
