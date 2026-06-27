/* =====================================================
 *  Path 80
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - formGetIptv (arg=1, call_ea=0x4fdd0, func_ea=0x4fce4, label=certain)
 *        call: GetValue("adv.iptv.stballvlans", stballvlans);
 *    - setIptvStb (arg=1, call_ea=0x4f8a8, func_ea=0x4f860, label=certain)
 *        call: SetValue("adv.iptv.stballvlans", iptv_stb_allvlans);
 *    - formSetIptv (arg=0, call_ea=0x4fbfc, func_ea=0x4f9b0, label=needs_check)
 *        call: setIptvStb(v5, v6, v7);
 *    - websGetVar (arg=ret, call_ea=0x4fa88, func_ea=source, label=source)
 *        call: v5 = websGetVar(wp, "list", &byte_794DF);
 * ===================================================== */


/* Function: formGetIptv @ 0x4FCE4 */
void __fastcall formGetIptv(webs_t wp, char_t *path, char_t *query)
{
  int mibname; // r0
  int v5; // r0
  const char *v6; // r1
  cJSON *Object; // r4
  cJSON *String; // r0
  cJSON *v9; // r0
  cJSON *v10; // r0
  cJSON *v11; // r0
  cJSON *v12; // r0
  cJSON *v13; // r0
  char *v14; // r5
  char_t *v15; // [sp+0h] [bp-280h]
  char_t *v16; // [sp+0h] [bp-280h]
  char stb_enable[8]; // [sp+10h] [bp-270h] BYREF
  char igmp_enable[8]; // [sp+18h] [bp-268h] BYREF
  char wl2g_mode[32]; // [sp+20h] [bp-260h] BYREF
  char wl5g_mode[32]; // [sp+40h] [bp-240h] BYREF
  char wl_mode[32]; // [sp+60h] [bp-220h] BYREF
  char stballvlans[256]; // [sp+80h] [bp-200h] BYREF
  char stbpvid[256]; // [sp+180h] [bp-100h] BYREF
  char citytag[256]; // [sp+280h] [bp+0h] BYREF
  char mib_name[256]; // [sp+380h] [bp+100h] BYREF

  memset(stb_enable, 0, sizeof(stb_enable));
  memset(igmp_enable, 0, sizeof(igmp_enable));
  memset(stballvlans, 0, sizeof(stballvlans));
  memset(stbpvid, 0, sizeof(stbpvid));
  memset(citytag, 0, sizeof(citytag));
  memset(wl2g_mode, 0, sizeof(wl2g_mode));
  memset(wl5g_mode, 0, sizeof(wl5g_mode));
  memset(wl_mode, 0, sizeof(wl_mode));
  memset(mib_name, 0, sizeof(mib_name));
  GetValue("iptv.stb.enable", stb_enable);
  GetValue("igmp.enable", igmp_enable);
  GetValue("adv.iptv.stballvlans", stballvlans);
  GetValue("adv.iptv.stbpvid", stbpvid);
  GetValue("iptv.city.vlan", citytag);
  mibname = wifi_get_mibname("wlan0", "workmode", mib_name);
  GetValue(mibname, wl2g_mode);
  v5 = wifi_get_mibname("wlan1", "workmode", mib_name);
  GetValue(v5, wl5g_mode);
  if ( !strcmp("ap", wl2g_mode) && !strcmp("ap", wl5g_mode) )
  {
    v6 = "ap";
LABEL_10:
    strcpy(wl_mode, v6);
    goto LABEL_11;
  }
  if ( !strcmp("wisp", wl2g_mode) || !strcmp("wisp", wl5g_mode) )
  {
    v6 = "wisp";
    goto LABEL_10;
  }
  if ( !strcmp("apclient", wl2g_mode) || !strcmp("apclient", wl5g_mode) )
  {
    v6 = "apclient";
    goto LABEL_10;
  }
LABEL_11:
  Object = cJSON_CreateObject();
  String = cJSON_CreateString(wl_mode);
  cJSON_AddItemToObject(Object, "wl_mode", String);
  v9 = cJSON_CreateString(stb_enable);
  cJSON_AddItemToObject(Object, "stbEn", v9);
  v10 = cJSON_CreateString(igmp_enable);
  cJSON_AddItemToObject(Object, "igmpEn", v10);
  v11 = cJSON_CreateString(citytag);
  cJSON_AddItemToObject(Object, "iptvType", v11);
  v12 = cJSON_CreateString(stbpvid);
  cJSON_AddItemToObject(Object, "vlanId", v12);
  v13 = cJSON_CreateString(stballvlans);
  cJSON_AddItemToObject(Object, "list", v13);
  v14 = cJSON_Print(Object);
  cJSON_Delete(Object);
  websWrite(wp, v15);
  websWrite(wp, v16);
  free(v14);
  websDone(wp, 200);
}


/* Function: setIptvStb @ 0x4F860 */
void __fastcall setIptvStb(char *iptv_stb_allvlans, char *iptv_stb_pvid, char *iptv_stb_citytag)
{
  char *v6; // r1

  SetValue("iptv.stb.enable", "1");
  if ( !strcmp(iptv_stb_citytag, "none") )
  {
    SetValue("adv.iptv.stballvlans", &byte_794DF);
    v6 = &byte_794DF;
  }
  else
  {
    SetValue("adv.iptv.stballvlans", iptv_stb_allvlans);
    v6 = iptv_stb_pvid;
  }
  SetValue("adv.iptv.stbpvid", v6);
}


/* Function: formSetIptv @ 0x4F9B0 */
void __fastcall formSetIptv(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r10
  char_t *v5; // r8
  char_t *v6; // r9
  char_t *v7; // r7
  _BOOL4 v8; // r5
  int v9; // r11
  int v10; // r0
  bool v11; // zf
  int v12; // r0
  char_t *igmp_enable; // [sp+0h] [bp-190h]
  char_t *igmp_enablea; // [sp+0h] [bp-190h]
  char *nptr; // [sp+8h] [bp-188h]
  char igmp_param[128]; // [sp+10h] [bp-180h] BYREF
  char stballvlans_before[256]; // [sp+90h] [bp-100h] BYREF
  char stbpvid_before[256]; // [sp+190h] [bp+0h] BYREF
  char citytag_before[256]; // [sp+290h] [bp+100h] BYREF
  char iptv_enable_before[260]; // [sp+390h] [bp+200h] BYREF

  memset(stballvlans_before, 0, sizeof(stballvlans_before));
  memset(stbpvid_before, 0, sizeof(stbpvid_before));
  memset(citytag_before, 0, sizeof(citytag_before));
  memset(iptv_enable_before, 0, 0x100u);
  memset(igmp_param, 0, sizeof(igmp_param));
  Var = websGetVar(wp, "stbEn", "0");
  nptr = websGetVar(wp, "igmpEn", "0");
  v5 = websGetVar(wp, "list", &byte_794DF);
  v6 = websGetVar(wp, "vlanId", &byte_794DF);
  v7 = websGetVar(wp, "iptvType", &byte_794DF);
  GetValue("adv.iptv.stballvlans", stballvlans_before);
  GetValue("adv.iptv.stbpvid", stbpvid_before);
  GetValue("iptv.city.vlan", citytag_before);
  GetValue("iptv.stb.enable", iptv_enable_before);
  v8 = strcmp(Var, iptv_enable_before)
    || strcmp(v5, stballvlans_before)
    || strcmp(v6, stbpvid_before)
    || strcmp(v7, citytag_before) != 0;
  SetValue("iptv.city.vlan", v7);
  v9 = atoi(nptr);
  v10 = atoi(Var);
  v11 = v10 == 1;
  if ( v10 != 1 )
    v11 = v9 == 1;
  if ( v11 )
  {
    SetValue("iptv.enable", "1");
    if ( v9 == 1 )
    {
      setIptvIgmp();
      sprintf(igmp_param, "op=%d", 1);
      goto LABEL_13;
    }
  }
  else
  {
    SetValue("iptv.enable", "0");
  }
  unsetIptvIgmp();
  sprintf(igmp_param, "op=%d", 2);
LABEL_13:
  if ( atoi(Var) == 1 )
    setIptvStb(v5, v6, v7);
  else
    unsetIptvStb(v5, v6, v7);
  v12 = printf("[he debug]:%s,%d--nvram commit ok!\n", "formSetIptv", 133);
  if ( CommitSyncCfm(v12) )
    send_msg_to_netctrl(26, igmp_param);
  websWrite(wp, igmp_enable);
  websWrite(wp, igmp_enablea);
  websDone(wp, 200);
  if ( v8 )
    systool_sys_handle(0);
}
