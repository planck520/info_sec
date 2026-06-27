/* =====================================================
 *  Path 127
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - formGetPPTPServer (arg=1, call_ea=0x49930, func_ea=0x497d0, label=certain)
 *        call: GetValue("vpn.ser.pptpdmppe.op", pptp_server_mppe_op);
 *    - formSetPPTPServer (arg=1, call_ea=0x48f54, func_ea=0x48bac, label=needs_check)
 *        call: SetValue("vpn.ser.pptpdmppe.op", v16);
 *    - websGetVar (arg=ret, call_ea=0x48de8, func_ea=source, label=source)
 *        call: v16 = websGetVar(wp, "mppeOp", "128");
 * ===================================================== */


/* Function: formGetPPTPServer @ 0x497D0 */
void __fastcall formGetPPTPServer(webs_t wp, char_t *path, char_t *query)
{
  cJSON *Array; // r11
  cJSON *Object; // r4
  cJSON *String; // r0
  cJSON *v6; // r0
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
  int v20; // r6
  int v21; // r0
  cJSON *v22; // r0
  cJSON *v23; // r0
  cJSON *v24; // r0
  int v25; // r5
  cJSON *v26; // r0
  char *v27; // r0
  char *v28; // r4
  cJSON *v29; // r4
  cJSON *v30; // r0
  cJSON *v31; // r0
  cJSON *v32; // r0
  cJSON *v33; // r0
  cJSON *v34; // r0
  cJSON *v35; // r0
  cJSON *v36; // r0
  double v37; // r0
  cJSON *Number; // r0
  char_t *wpa; // [sp+0h] [bp-94h]
  char_t *wpb; // [sp+0h] [bp-94h]
  char pptp_server_enable[4]; // [sp+34h] [bp-60h] BYREF
  char pptp_server_wanid[4]; // [sp+38h] [bp-5Ch] BYREF
  char pptp_server_mppe[4]; // [sp+3Ch] [bp-58h] BYREF
  char pptp_server_mppe_op[4]; // [sp+40h] [bp-54h] BYREF
  char pptp_server_start_each_ip[4][4]; // [sp+44h] [bp-50h] BYREF
  char sys_mode[16]; // [sp+54h] [bp-40h] BYREF
  char conn_type[16]; // [sp+64h] [bp-30h] BYREF
  char pptp_server_start_ip[32]; // [sp+74h] [bp-20h] BYREF
  char pptp_server_end_ip[32]; // [sp+94h] [bp+0h] BYREF
  char lanIP[32]; // [sp+B4h] [bp+20h] BYREF
  char lanMask[32]; // [sp+D4h] [bp+40h] BYREF
  char guestIP[32]; // [sp+F4h] [bp+60h] BYREF
  char guestMask[32]; // [sp+114h] [bp+80h] BYREF
  char wanIp[32]; // [sp+134h] [bp+A0h] BYREF
  char wanMask[32]; // [sp+154h] [bp+C0h] BYREF
  char serverip[32]; // [sp+174h] [bp+E0h] BYREF
  char vlan2ip[32]; // [sp+194h] [bp+100h] BYREF
  char vlan2mask[32]; // [sp+1B4h] [bp+120h] BYREF
  char pptpSvrIp[32]; // [sp+1D4h] [bp+140h] BYREF
  char pptp_server_each_ip[2][32]; // [sp+1F4h] [bp+160h] BYREF
  char pptp_server_c_ip[128]; // [sp+234h] [bp+1A0h] BYREF
  char wan_num[128]; // [sp+2B4h] [bp+220h] BYREF
  WAN_STATUS_INFO_STRU wan_status; // [sp+334h] [bp+2A0h] BYREF
  char pptp_users[256]; // [sp+428h] [bp+394h] BYREF
  char pptp_users_each[8][64]; // [sp+528h] [bp+494h] BYREF

  *(_DWORD *)pptp_server_enable = 0;
  *(_DWORD *)pptp_server_wanid = 0;
  *(_DWORD *)pptp_server_mppe = 0;
  *(_DWORD *)pptp_server_mppe_op = 0;
  memset(pptp_server_c_ip, 0, sizeof(pptp_server_c_ip));
  memset(pptp_server_start_ip, 0, sizeof(pptp_server_start_ip));
  memset(pptp_server_end_ip, 0, sizeof(pptp_server_end_ip));
  memset(lanIP, 0, sizeof(lanIP));
  memset(lanMask, 0, sizeof(lanMask));
  memset(guestIP, 0, sizeof(guestIP));
  memset(guestMask, 0, sizeof(guestMask));
  memset(wan_num, 0, sizeof(wan_num));
  memset(sys_mode, 0, sizeof(sys_mode));
  memset(conn_type, 0, sizeof(conn_type));
  GetValue("vpn.ser.pptpdEnable", pptp_server_enable);
  GetValue("vpn.ser.pptpwanid", pptp_server_wanid);
  GetValue("vpn.ser.pptpdmppe", pptp_server_mppe);
  GetValue("vpn.ser.pptpdmppe.op", pptp_server_mppe_op);
  GetValue("vpn.ser.pptpipcli", pptp_server_c_ip);
  if ( pptp_server_c_ip[0] )
  {
    _isoc99_sscanf(pptp_server_c_ip, "%[^-]-%s", pptp_server_each_ip, pptp_server_each_ip[1]);
    _isoc99_sscanf(
      (char *)pptp_server_each_ip,
      "%[^.].%[^.].%[^.].%s",
      pptp_server_start_each_ip,
      pptp_server_start_each_ip[1],
      pptp_server_start_each_ip[2],
      pptp_server_start_each_ip[3]);
    strcpy(pptp_server_start_ip, pptp_server_each_ip[0]);
    sprintf(
      pptp_server_end_ip,
      "%s.%s.%s.%s",
      pptp_server_start_each_ip[0],
      pptp_server_start_each_ip[1],
      pptp_server_start_each_ip[2],
      pptp_server_each_ip[1]);
  }
  else
  {
    strcpy(pptp_server_start_ip, "10.0.0.100");
    strcpy(pptp_server_end_ip, "10.0.0.200");
  }
  Array = cJSON_CreateArray();
  Object = cJSON_CreateObject();
  cJSON_AddItemToArray(Array, Object);
  String = cJSON_CreateString(pptp_server_enable);
  cJSON_AddItemToObject(Object, "serverEn", String);
  v6 = cJSON_CreateString(pptp_server_wanid);
  cJSON_AddItemToObject(Object, "wanid", v6);
  v7 = cJSON_CreateString(pptp_server_mppe);
  cJSON_AddItemToObject(Object, "mppe", v7);
  v8 = cJSON_CreateString(pptp_server_mppe_op);
  cJSON_AddItemToObject(Object, "mppeOp", v8);
  v9 = cJSON_CreateString(pptp_server_start_ip);
  cJSON_AddItemToObject(Object, "startIp", v9);
  v10 = cJSON_CreateString(pptp_server_end_ip);
  cJSON_AddItemToObject(Object, "endIp", v10);
  GetValue("lan.ip", lanIP);
  v11 = cJSON_CreateString(lanIP);
  cJSON_AddItemToObject(Object, "lanIp", v11);
  GetValue("lan.mask", lanMask);
  v12 = cJSON_CreateString(lanMask);
  cJSON_AddItemToObject(Object, "lanMask", v12);
  GetValue("wl.guest.dhcps_ip", guestIP);
  v13 = cJSON_CreateString(guestIP);
  cJSON_AddItemToObject(Object, "guestIp", v13);
  GetValue("wl.guest.dhcps_mask", guestMask);
  v14 = cJSON_CreateString(guestMask);
  cJSON_AddItemToObject(Object, "guestMask", v14);
  memset(wanIp, 0, sizeof(wanIp));
  memset(wanMask, 0, sizeof(wanMask));
  memset(serverip, 0, sizeof(serverip));
  memset(vlan2ip, 0, sizeof(vlan2ip));
  memset(vlan2mask, 0, sizeof(vlan2mask));
  cgiGetWanIpAndMask(wanIp, wanMask, serverip, vlan2ip, vlan2mask);
  v15 = cJSON_CreateString(serverip);
  cJSON_AddItemToObject(Object, "serverIp", v15);
  v16 = cJSON_CreateString(vlan2ip);
  cJSON_AddItemToObject(Object, "vlan2Ip", v16);
  v17 = cJSON_CreateString(vlan2mask);
  cJSON_AddItemToObject(Object, "vlan2Mask", v17);
  v18 = cJSON_CreateString(wanIp);
  cJSON_AddItemToObject(Object, "wanIp", v18);
  v19 = cJSON_CreateString(wanMask);
  cJSON_AddItemToObject(Object, "wanMask", v19);
  GetValue("wans.flag", wan_num);
  GetValue("sys.mode", sys_mode);
  if ( atoi(wan_num) == 2 )
  {
    memset(&wan_status, 0, sizeof(wan_status));
    memset(conn_type, 0, sizeof(conn_type));
    GetValue("wan2.connecttype", conn_type);
    v20 = atoi(conn_type);
    v21 = atoi(sys_mode);
    file_wan_status_info_get(0, v20, 2, v21, &wan_status);
    v22 = cJSON_CreateString(wan_status.ip_info.wan_ip);
    cJSON_AddItemToObject(Object, "wanIp2", v22);
    v23 = cJSON_CreateString(wan_status.ip_info.wan_mask);
    cJSON_AddItemToObject(Object, "wanMask2", v23);
  }
  memset(pptpSvrIp, 0, sizeof(pptpSvrIp));
  GetValue("vpn.ser.pptpserver", pptpSvrIp);
  v24 = cJSON_CreateString(pptpSvrIp);
  v25 = 0;
  cJSON_AddItemToObject(Object, "pptpSvrIp", v24);
  v26 = cJSON_CreateString("255.255.255.0");
  cJSON_AddItemToObject(Object, "pptpSvrMask", v26);
  do
  {
    memset(pptp_users, 0, sizeof(pptp_users));
    memset(pptp_users_each, 0, sizeof(pptp_users_each));
    v27 = racat("vpn.ser.pptpuser", v25);
    GetValue(v27, pptp_users);
    if ( !pptp_users[0] )
      break;
    getEachListFromMib(pptp_users, pptp_users_each);
    v29 = cJSON_CreateObject();
    ++v25;
    cJSON_AddItemToArray(Array, v29);
    v30 = cJSON_CreateString(pptp_users_each[2]);
    cJSON_AddItemToObject(v29, "userName", v30);
    v31 = cJSON_CreateString(pptp_users_each[4]);
    cJSON_AddItemToObject(v29, "password", v31);
    v32 = cJSON_CreateString(pptp_users_each[0]);
    cJSON_AddItemToObject(v29, "enable", v32);
    v33 = cJSON_CreateString(pptp_users_each[3]);
    cJSON_AddItemToObject(v29, "netEn", v33);
    v34 = cJSON_CreateString(pptp_users_each[5]);
    cJSON_AddItemToObject(v29, "serverIp", v34);
    v35 = cJSON_CreateString(pptp_users_each[6]);
    cJSON_AddItemToObject(v29, "serverMask", v35);
    v36 = cJSON_CreateString(pptp_users_each[7]);
    cJSON_AddItemToObject(v29, "remark", v36);
    v37 = (double)check_pptp_user_if_login(pptp_users_each[2]);
    Number = cJSON_CreateNumber(v37);
    cJSON_AddItemToObject(v29, "connsta", Number);
  }
  while ( v25 != 8 );
  v28 = cJSON_Print(Array);
  cJSON_Delete(Array);
  websWrite(wp, wpa);
  websWrite(wp, wpb);
  free(v28);
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
