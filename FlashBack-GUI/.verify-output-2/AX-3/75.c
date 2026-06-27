/* =====================================================
 *  Path 75
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - formGetAdvanceStatus (arg=1, call_ea=0x5ea4c, func_ea=0x5e8c0, label=certain)
 *        call: GetValue("adv.ddns1.en", ddns);
 *    - formSetSysToolDDNS (arg=1, call_ea=0x50420, func_ea=0x5035c, label=certain)
 *        call: SetValue("adv.ddns1.en", Var);
 *    - websGetVar (arg=ret, call_ea=0x503b4, func_ea=source, label=source)
 *        call: Var = websGetVar(wp, "ddnsEn", "0");
 * ===================================================== */


/* Function: formGetAdvanceStatus @ 0x5E8C0 */
void __fastcall formGetAdvanceStatus(webs_t wp, char_t *path, char_t *query)
{
  cJSON *Object; // r4
  const char *v5; // r1
  int mibname; // r0
  int v7; // r0
  const char *v8; // r1
  cJSON *String; // r2
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
  const char *v21; // r0
  cJSON *v22; // r0
  const char *v23; // r0
  cJSON *v24; // r0
  const char *v25; // r0
  cJSON *v26; // r0
  const char *v27; // r0
  cJSON *v28; // r0
  cJSON *v29; // r0
  char *v30; // r5
  char_t *v31; // [sp+0h] [bp-2A0h]
  char_t *v32; // [sp+0h] [bp-2A0h]
  char netControl[8]; // [sp+20h] [bp-280h] BYREF
  char led[8]; // [sp+28h] [bp-278h] BYREF
  char cloud[8]; // [sp+30h] [bp-270h] BYREF
  char sleepMode[8]; // [sp+38h] [bp-268h] BYREF
  char remoteWeb[8]; // [sp+40h] [bp-260h] BYREF
  char ddns[8]; // [sp+48h] [bp-258h] BYREF
  char upnp[8]; // [sp+50h] [bp-250h] BYREF
  char iptv[8]; // [sp+58h] [bp-248h] BYREF
  char staticroute[8]; // [sp+60h] [bp-240h] BYREF
  char virtarlser[8]; // [sp+68h] [bp-238h] BYREF
  char dmz_en[8]; // [sp+70h] [bp-230h] BYREF
  char wl24g_work_mode[24]; // [sp+78h] [bp-228h] BYREF
  char wl5g_work_mode[24]; // [sp+90h] [bp-210h] BYREF
  char wl_mode[24]; // [sp+A8h] [bp-1F8h] BYREF
  char mib_value[32]; // [sp+C0h] [bp-1E0h] BYREF
  char userpass[64]; // [sp+E0h] [bp-1C0h] BYREF
  char tr69_enable[128]; // [sp+120h] [bp-180h] BYREF
  char mac_filter_mode[256]; // [sp+1A0h] [bp-100h] BYREF
  char mib_name[256]; // [sp+2A0h] [bp+0h] BYREF

  memset(netControl, 0, sizeof(netControl));
  memset(led, 0, sizeof(led));
  memset(cloud, 0, sizeof(cloud));
  memset(sleepMode, 0, sizeof(sleepMode));
  memset(remoteWeb, 0, sizeof(remoteWeb));
  memset(ddns, 0, sizeof(ddns));
  memset(upnp, 0, sizeof(upnp));
  memset(iptv, 0, sizeof(iptv));
  memset(staticroute, 0, sizeof(staticroute));
  memset(virtarlser, 0, sizeof(virtarlser));
  memset(mib_value, 0, sizeof(mib_value));
  memset(wl24g_work_mode, 0, sizeof(wl24g_work_mode));
  memset(wl5g_work_mode, 0, sizeof(wl5g_work_mode));
  memset(wl_mode, 0, sizeof(wl_mode));
  memset(userpass, 0, sizeof(userpass));
  memset(dmz_en, 0, sizeof(dmz_en));
  memset(mac_filter_mode, 0, sizeof(mac_filter_mode));
  memset(mib_name, 0, sizeof(mib_name));
  memset(tr69_enable, 0, sizeof(tr69_enable));
  Object = cJSON_CreateObject();
  GetValue("adv.qos.en", netControl);
  GetValue("ucloud.en", cloud);
  GetValue("sys.powersleep.enable", sleepMode);
  GetValue("wans.wanweben", remoteWeb);
  GetValue("adv.ddns1.en", ddns);
  GetValue("adv.upnp.en", upnp);
  GetValue("iptv.enable", iptv);
  GetValue("sys.sched.led.type", mib_value);
  GetValue("adv.staticroute.listnum", staticroute);
  GetValue("adv.virtualser.listnum", virtarlser);
  if ( !strncmp(mib_value, "open", 4u) )
    v5 = "0";
  else
    v5 = "1";
  strcpy(led, v5);
  mibname = wifi_get_mibname("wlan0", "workmode", mib_name);
  GetValue(mibname, wl24g_work_mode);
  v7 = wifi_get_mibname("wlan1", "workmode", mib_name);
  GetValue(v7, wl5g_work_mode);
  if ( !strcmp(wl24g_work_mode, "wisp") || !strcmp(wl5g_work_mode, "wisp") )
  {
    v8 = "wisp";
  }
  else if ( !strcmp(wl24g_work_mode, "apclient") || !strcmp(wl5g_work_mode, "apclient") )
  {
    v8 = "apclient";
  }
  else
  {
    v8 = "ap";
  }
  strcpy(wl_mode, v8);
  GetValue("wan1.dmzen", dmz_en);
  GetValue("sys.userpass", userpass);
  if ( userpass[0] )
    String = cJSON_CreateString("false");
  else
    String = cJSON_CreateString("true");
  cJSON_AddItemToObject(Object, "nopwd", String);
  GetValue("cwmp.manage.enable", tr69_enable);
  v10 = cJSON_CreateString(tr69_enable);
  cJSON_AddItemToObject(Object, "tr069", v10);
  v11 = cJSON_CreateString(netControl);
  cJSON_AddItemToObject(Object, "netControl", v11);
  v12 = cJSON_CreateString(led);
  cJSON_AddItemToObject(Object, "led", v12);
  v13 = cJSON_CreateString(cloud);
  cJSON_AddItemToObject(Object, "cloud", v13);
  v14 = cJSON_CreateString(sleepMode);
  cJSON_AddItemToObject(Object, "sleepMode", v14);
  v15 = cJSON_CreateString(remoteWeb);
  cJSON_AddItemToObject(Object, "remoteWeb", v15);
  v16 = cJSON_CreateString(ddns);
  cJSON_AddItemToObject(Object, "ddns", v16);
  v17 = cJSON_CreateString(upnp);
  cJSON_AddItemToObject(Object, "upnp", v17);
  v18 = cJSON_CreateString(iptv);
  cJSON_AddItemToObject(Object, "iptv", v18);
  v19 = cJSON_CreateString(wl_mode);
  cJSON_AddItemToObject(Object, "wl_mode", v19);
  v20 = cJSON_CreateString(dmz_en);
  cJSON_AddItemToObject(Object, "dmz", v20);
  if ( GetParentCtrlStatus() )
    v21 = "1";
  else
    v21 = "0";
  v22 = cJSON_CreateString(v21);
  cJSON_AddItemToObject(Object, "parentControl", v22);
  if ( firewall_status() )
    v23 = "1";
  else
    v23 = "0";
  v24 = cJSON_CreateString(v23);
  cJSON_AddItemToObject(Object, "firewall", v24);
  if ( atoi(staticroute) )
    v25 = "1";
  else
    v25 = "0";
  v26 = cJSON_CreateString(v25);
  cJSON_AddItemToObject(Object, "staticRoute", v26);
  if ( atoi(virtarlser) )
    v27 = "1";
  else
    v27 = "0";
  v28 = cJSON_CreateString(v27);
  cJSON_AddItemToObject(Object, "virtualServer", v28);
  get_macfilter_mode(mac_filter_mode);
  v29 = cJSON_CreateString(mac_filter_mode);
  cJSON_AddItemToObject(Object, "macFilterType", v29);
  v30 = cJSON_Print(Object);
  cJSON_Delete(Object);
  websWrite(wp, v31);
  websWrite(wp, v32);
  free(v30);
  websDone(wp, 200);
}


/* Function: formSetSysToolDDNS @ 0x5035C */
void __fastcall formSetSysToolDDNS(webs_t wp, char_t *path, char_t *query)
{
  char_t *v4; // r11
  char_t *v5; // r10
  char_t *v6; // r9
  char_t *v7; // r8
  char_t *v8; // r11
  char_t *v9; // r10
  char_t *v10; // r9
  char_t *v11; // r8
  char_t *v12; // r11
  char_t *v13; // r10
  char_t *v14; // r9
  char_t *v15; // r8
  char_t *v16; // r11
  char_t *v17; // r10
  char_t *v18; // r9
  char_t *v19; // r8
  char_t *v20; // r11
  char_t *v21; // r10
  char_t *v22; // r9
  char_t *v23; // r8
  char_t *v24; // r5
  int v25; // r0
  int v26; // r2
  char_t *Var; // [sp+8h] [bp-44h]
  char_t *v28; // [sp+8h] [bp-44h]
  char_t *v29; // [sp+8h] [bp-44h]
  char_t *v30; // [sp+8h] [bp-44h]
  char ret_buf[64]; // [sp+Ch] [bp-40h] BYREF
  char param_str[260]; // [sp+4Ch] [bp+0h] BYREF

  memset(ret_buf, 0, sizeof(ret_buf));
  memset(param_str, 0, 0x100u);
  Var = websGetVar(wp, "ddnsEn", "0");
  v4 = websGetVar(wp, "serverName", "0");
  v5 = websGetVar(wp, "ddnsUser", "0");
  v6 = websGetVar(wp, "ddnsPwd", "0");
  v7 = websGetVar(wp, "ddnsDomain", "0");
  SetValue("adv.ddns1.en", Var);
  SetValue("adv.ddns1.type", v4);
  SetValue("adv.ddns1.user", v5);
  SetValue("adv.ddns1.pwd", v6);
  SetValue("adv.ddns1.domain", v7);
  v28 = websGetVar(wp, "check2", "0");
  v8 = websGetVar(wp, "serverName2", "0");
  v9 = websGetVar(wp, "userName2", "0");
  v10 = websGetVar(wp, "password2", "0");
  v11 = websGetVar(wp, "remark2", "0");
  SetValue("adv.ddns2.en", v28);
  SetValue("adv.ddns2.type", v8);
  SetValue("adv.ddns2.user", v9);
  SetValue("adv.ddns2.pwd", v10);
  SetValue("adv.ddns2.domain", v11);
  v29 = websGetVar(wp, "check3", "0");
  v12 = websGetVar(wp, "serverName3", "0");
  v13 = websGetVar(wp, "userName3", "0");
  v14 = websGetVar(wp, "password3", "0");
  v15 = websGetVar(wp, "remark3", "0");
  SetValue("adv.ddns3.en", v29);
  SetValue("adv.ddns3.type", v12);
  SetValue("adv.ddns3.user", v13);
  SetValue("adv.ddns3.pwd", v14);
  SetValue("adv.ddns3.domain", v15);
  v30 = websGetVar(wp, "check4", "0");
  v16 = websGetVar(wp, "serverName4", "0");
  v17 = websGetVar(wp, "userName4", "0");
  v18 = websGetVar(wp, "password4", "0");
  v19 = websGetVar(wp, "remark4", "0");
  SetValue("adv.ddns4.en", v30);
  SetValue("adv.ddns4.type", v16);
  SetValue("adv.ddns4.user", v17);
  SetValue("adv.ddns4.pwd", v18);
  SetValue("adv.ddns4.domain", v19);
  v20 = websGetVar(wp, "check5", "0");
  v21 = websGetVar(wp, "serverName5", "0");
  v22 = websGetVar(wp, "userName5", "0");
  v23 = websGetVar(wp, "password5", "0");
  v24 = websGetVar(wp, "remark5", "0");
  SetValue("adv.ddns5.en", v20);
  SetValue("adv.ddns5.type", v21);
  SetValue("adv.ddns5.user", v22);
  SetValue("adv.ddns5.pwd", v23);
  v25 = SetValue("adv.ddns5.domain", v24);
  if ( CommitCfm(v25) )
  {
    sprintf(param_str, "advance_type=%d", 6);
    send_msg_to_netctrl(5, param_str);
    v26 = 0;
  }
  else
  {
    v26 = 1;
  }
  sprintf(ret_buf, "{\"errCode\":%d}", v26);
  websTransfer(wp, ret_buf);
}
