/* =====================================================
 *  Path 122
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - formGetSysToolDDNS (arg=1, call_ea=0x50a6c, func_ea=0x509cc, label=certain)
 *        call: GetValue("adv.ddns1.type", server_name);
 *    - formSetSysToolDDNS (arg=1, call_ea=0x50430, func_ea=0x5035c, label=certain)
 *        call: SetValue("adv.ddns1.type", v4);
 *    - websGetVar (arg=ret, call_ea=0x503c8, func_ea=source, label=source)
 *        call: v4 = websGetVar(wp, "serverName", "0");
 * ===================================================== */


/* Function: formGetSysToolDDNS @ 0x509CC */
void __fastcall formGetSysToolDDNS(webs_t wp, char_t *path, char_t *query)
{
  cJSON *Object; // r5
  int DDNSConnStatus; // r0
  cJSON *String; // r0
  cJSON *v6; // r0
  cJSON *v7; // r0
  cJSON *v8; // r0
  cJSON *v9; // r0
  cJSON *v10; // r0
  char *v11; // r0
  char ddns_en[8]; // [sp+Ch] [bp-178h] BYREF
  char ddns_status[8]; // [sp+14h] [bp-170h] BYREF
  char server_name[64]; // [sp+1Ch] [bp-168h] BYREF
  char ddns_user[64]; // [sp+5Ch] [bp-128h] BYREF
  char ddns_pwd[64]; // [sp+9Ch] [bp-E8h] BYREF
  char ddns_domain[128]; // [sp+DCh] [bp-A8h] BYREF

  Object = cJSON_CreateObject();
  memset(ddns_en, 0, sizeof(ddns_en));
  memset(server_name, 0, sizeof(server_name));
  memset(ddns_user, 0, sizeof(ddns_user));
  memset(ddns_pwd, 0, sizeof(ddns_pwd));
  memset(ddns_domain, 0, sizeof(ddns_domain));
  memset(ddns_status, 0, sizeof(ddns_status));
  GetValue("adv.ddns1.en", ddns_en);
  GetValue("adv.ddns1.type", server_name);
  GetValue("adv.ddns1.user", ddns_user);
  GetValue("adv.ddns1.pwd", ddns_pwd);
  GetValue("adv.ddns1.domain", ddns_domain);
  DDNSConnStatus = getDDNSConnStatus();
  sprintf(ddns_status, "%d", DDNSConnStatus);
  String = cJSON_CreateString(ddns_en);
  cJSON_AddItemToObject(Object, "ddnsEn", String);
  v6 = cJSON_CreateString(server_name);
  cJSON_AddItemToObject(Object, "serverName", v6);
  v7 = cJSON_CreateString(ddns_user);
  cJSON_AddItemToObject(Object, "ddnsUser", v7);
  v8 = cJSON_CreateString(ddns_pwd);
  cJSON_AddItemToObject(Object, "ddnsPwd", v8);
  v9 = cJSON_CreateString(ddns_domain);
  cJSON_AddItemToObject(Object, "ddnsDomain", v9);
  v10 = cJSON_CreateString(ddns_status);
  cJSON_AddItemToObject(Object, "ddnsStatus", v10);
  v11 = cJSON_Object_2String(Object);
  websTransfer(wp, v11);
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
