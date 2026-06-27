/* =====================================================
 *  Path 108
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - formGetSafeWanWebMan (arg=1, call_ea=0x54080, func_ea=0x53f70, label=certain)
 *        call: GetValue("wans.wanwebport", remote_port);
 *    - formSetSafeWanWebMan (arg=1, call_ea=0x53edc, func_ea=0x53dcc, label=certain)
 *        call: v8 = SetValue("wans.wanwebport", v7);
 *    - websGetVar (arg=ret, call_ea=0x53e64, func_ea=source, label=source)
 *        call: v7 = websGetVar(wp, "remotePort", &byte_794DF);
 * ===================================================== */


/* Function: formGetSafeWanWebMan @ 0x53F70 */
void __fastcall formGetSafeWanWebMan(webs_t wp, char_t *path, char_t *query)
{
  cJSON *Object; // r4
  const char *v5; // r0
  cJSON *String; // r0
  cJSON *v7; // r0
  cJSON *v8; // r0
  cJSON *v9; // r0
  cJSON *v10; // r0
  cJSON *v11; // r0
  cJSON *v12; // r0
  char *v13; // r0
  char remote_web_en[8]; // [sp+Ch] [bp-ACh] BYREF
  char remote_port[8]; // [sp+14h] [bp-A4h] BYREF
  char lan_ip[16]; // [sp+1Ch] [bp-9Ch] BYREF
  char lan_mask[16]; // [sp+2Ch] [bp-8Ch] BYREF
  char wl_guest_ip[16]; // [sp+3Ch] [bp-7Ch] BYREF
  char remote_ip[32]; // [sp+4Ch] [bp-6Ch] BYREF
  char sys_passwd[36]; // [sp+6Ch] [bp-4Ch] BYREF

  Object = cJSON_CreateObject();
  memset(lan_ip, 0, sizeof(lan_ip));
  memset(lan_mask, 0, sizeof(lan_mask));
  memset(wl_guest_ip, 0, sizeof(wl_guest_ip));
  memset(remote_web_en, 0, sizeof(remote_web_en));
  memset(remote_ip, 0, sizeof(remote_ip));
  memset(remote_port, 0, sizeof(remote_port));
  memset(sys_passwd, 0, sizeof(sys_passwd));
  GetValue("sys.userpass", sys_passwd);
  GetValue("lan.ip", lan_ip);
  GetValue("lan.mask", lan_mask);
  GetValue("wl.guest.dhcps_ip", wl_guest_ip);
  GetValue("wans.wanweben", remote_web_en);
  GetValue("wans.wanwebip", remote_ip);
  GetValue("wans.wanwebport", remote_port);
  if ( sys_passwd[0] )
    v5 = "1";
  else
    v5 = "0";
  String = cJSON_CreateString(v5);
  cJSON_AddItemToObject(Object, "syspwdflag", String);
  v7 = cJSON_CreateString(lan_ip);
  cJSON_AddItemToObject(Object, "lanIp", v7);
  v8 = cJSON_CreateString(lan_mask);
  cJSON_AddItemToObject(Object, "lanMask", v8);
  v9 = cJSON_CreateString(wl_guest_ip);
  cJSON_AddItemToObject(Object, "wlGuestIp", v9);
  v10 = cJSON_CreateString(remote_web_en);
  cJSON_AddItemToObject(Object, "remoteWebEn", v10);
  v11 = cJSON_CreateString(remote_ip);
  cJSON_AddItemToObject(Object, "remoteIp", v11);
  v12 = cJSON_CreateString(remote_port);
  cJSON_AddItemToObject(Object, "remotePort", v12);
  v13 = cJSON_Object_2String(Object);
  websTransfer(wp, v13);
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
