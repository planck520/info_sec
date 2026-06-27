/* =====================================================
 *  Path 57
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - write_online_upgrade_info (arg=1, call_ea=0x5a0a8, func_ea=0x5a028, label=needs_check)
 *        call: GetValue("not.notice.version", not_now_value);
 *    - formsetNotUpgrade (arg=1, call_ea=0x5cce0, func_ea=0x5cc1c, label=needs_check)
 *        call: v6 = SetValue("not.notice.version", Var);
 *    - websGetVar (arg=ret, call_ea=0x5cc70, func_ea=source, label=source)
 *        call: Var = websGetVar(wp, "newVersion", &byte_794DF);
 * ===================================================== */


/* Function: write_online_upgrade_info @ 0x5A028 */
void __fastcall write_online_upgrade_info(cJSON_0 **root, WANERRINFO err)
{
  void *v3; // r0
  cJSON *Object; // r4
  cJSON *String; // r2
  const char *v6; // r0
  cJSON *v7; // r0
  cJSON *v8; // r0
  char not_now_value[64]; // [sp+4h] [bp-184h] BYREF
  device_info dev_info; // [sp+44h] [bp-144h] BYREF

  v3 = memset(not_now_value, 0, sizeof(not_now_value));
  if ( is_need_check_11444 == 1 && is_wan_onlined(v3) == 1 )
  {
    query_version2(&mess_11442);
    if ( mess_11442.new_ver == 1 )
      is_need_check_11444 = 0;
  }
  Object = cJSON_CreateObject();
  if ( Object )
  {
    GetValue("not.notice.version", not_now_value);
    memset(&dev_info, 0, sizeof(dev_info));
    get_device_info(0, &dev_info);
    if ( !memcmp(dev_info.firmware_version, mess_11442.new_version, 0xCu)
      || !strcmp(not_now_value, mess_11442.new_version) )
    {
      String = cJSON_CreateString("0");
    }
    else
    {
      if ( mess_11442.new_ver )
        v6 = "1";
      else
        v6 = "0";
      String = cJSON_CreateString(v6);
    }
    cJSON_AddItemToObject(Object, "newVersionExist", String);
    v7 = cJSON_CreateString(mess_11442.new_version);
    cJSON_AddItemToObject(Object, "newVersion", v7);
    v8 = cJSON_CreateString(dev_info.firmware_version);
    cJSON_AddItemToObject(Object, "curVersion", v8);
    cJSON_AddItemToObject((cJSON *)*root, "onlineUpgradeInfo", Object);
  }
}


/* Function: formsetNotUpgrade @ 0x5CC1C */
void __fastcall formsetNotUpgrade(webs_t wp, char_t *path, char_t *query)
{
  char_t *Var; // r7
  char_t *v5; // r0
  int v6; // r0
  int v7; // r0
  char new_version[128]; // [sp+0h] [bp-198h] BYREF
  char tmp[256]; // [sp+80h] [bp-118h] BYREF

  memset(tmp, 0, sizeof(tmp));
  memset(new_version, 0, sizeof(new_version));
  Var = websGetVar(wp, "newVersion", &byte_794DF);
  v5 = websGetVar(wp, "action", &byte_794DF);
  v6 = strcmp(v5, "1");
  if ( !v6 )
  {
    if ( !*Var )
    {
      Var = new_version;
      GetValue("uc_new_version", new_version);
      printf("[%s:%d] faile to get new version from web, set version as:%s!\n", "formsetNotUpgrade", 1170, new_version);
    }
    v6 = SetValue("not.notice.version", Var);
  }
  v7 = CommitCfm(v6);
  sprintf(tmp, "{\"errCode\":%d}", v7 == 0);
  websTransfer(wp, tmp);
}
