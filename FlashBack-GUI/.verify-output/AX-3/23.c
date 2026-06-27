/* =====================================================
 *  Path 23
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = websGetVar
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - set_qosMib_list (arg=1, call_ea=0x4d2ac, func_ea=0x4d1d0, label=needs_check)
 *        call: strcpy(qos_str, list);
 *    - formSetQosBand (arg=0, call_ea=0x5efec, func_ea=0x5ef74, label=certain)
 *        call: set_qosMib_list(Var, 10);
 *    - websGetVar (arg=ret, call_ea=0x5efd0, func_ea=source, label=source)
 *        call: Var = websGetVar(wp, "list", &byte_794DF);
 * ===================================================== */


/* Function: set_qosMib_list @ 0x4D1D0 */
void __fastcall set_qosMib_list(char *list, char c)
{
  char *v3; // r0
  char *v4; // r9
  int v5; // r11
  int v6; // [sp+8h] [bp-288h]
  int num; // [sp+1Ch] [bp-274h] BYREF
  char limit_en[8]; // [sp+20h] [bp-270h] BYREF
  char tmp_drate[16]; // [sp+28h] [bp-268h] BYREF
  char tmp_urate[16]; // [sp+38h] [bp-258h] BYREF
  char mac[32]; // [sp+48h] [bp-248h] BYREF
  char qos_str[256]; // [sp+68h] [bp-228h] BYREF
  char tmp_devname[256]; // [sp+168h] [bp-128h] BYREF

  v6 = c;
  num = 0;
  memset(qos_str, 0, sizeof(qos_str));
  memset(limit_en, 0, sizeof(limit_en));
  memset(mac, 0, sizeof(mac));
  memset(tmp_drate, 0, sizeof(tmp_drate));
  memset(tmp_urate, 0, sizeof(tmp_urate));
  memset(tmp_devname, 0, sizeof(tmp_devname));
  while ( 1 )
  {
    v3 = strchr(list, v6);
    if ( !v3 )
      break;
    v4 = v3 + 1;
    *v3 = 0;
    memset(qos_str, 0, sizeof(qos_str));
    strcpy(qos_str, list);
    if ( qos_str[0] == 59 )
    {
      v5 = 0;
      _isoc99_sscanf(qos_str, ";%[^;];%[^;];%[^;];%[^;];", limit_en, mac, tmp_urate, tmp_drate);
    }
    else
    {
      v5 = 1;
      _isoc99_sscanf(qos_str, "%[^\r]\r%[^\r]\r%[^\r]\r%s", tmp_devname, mac, tmp_urate, tmp_drate);
    }
    if ( atoi(tmp_urate) || atoi(tmp_drate) )
    {
      if ( v5 == 1 )
        set_device_name(tmp_devname, mac);
      setOneClientQos(1, mac, tmp_urate, tmp_drate);
      if ( ++num > 29 )
      {
        list = v4;
        break;
      }
    }
    list = v4;
  }
  if ( num == 30 )
    printf(
      "%s[%s:%s:%d] %sqos rule spports only 30 iterms!\n\x1B[0m",
      "\x1B[0;33m",
      "cgi",
      "set_qosMib_list",
      469,
      "\x1B[0;31m");
  else
    set_client_qos(list, &num);
  set_qos_enable(num);
}


/* Function: formSetQosBand @ 0x5EF74 */
void __fastcall formSetQosBand(webs_t wp, char_t *path, char_t *query)
{
  char *Var; // r4
  int v5; // r0
  int v6; // r2
  char cgi_debug[16]; // [sp+10h] [bp-190h] BYREF
  char ret_buf[32]; // [sp+20h] [bp-180h] BYREF
  char guest_down_speed[32]; // [sp+40h] [bp-160h] BYREF
  char guest_up_speed[32]; // [sp+60h] [bp-140h] BYREF
  char msg_info[256]; // [sp+80h] [bp-120h] BYREF

  memset(ret_buf, 0, sizeof(ret_buf));
  memset(msg_info, 0, sizeof(msg_info));
  Var = websGetVar(wp, "list", &byte_794DF);
  unSetQosOldMiblist();
  set_qosoldMib_list();
  unSetQosMiblist();
  set_qosMib_list(Var, 10);
  memset(guest_down_speed, 0, sizeof(guest_down_speed));
  memset(guest_up_speed, 0, sizeof(guest_up_speed));
  GetValue("wl.guest.down_speed", guest_down_speed);
  memset(cgi_debug, 0, sizeof(cgi_debug));
  if ( GetValue("cgi_debug", cgi_debug) && !strcmp("on", cgi_debug) )
    printf(
      "%s[%s:%s:%d] %s%s == %s\n\x1B[0m",
      "\x1B[0;33m",
      "cgi",
      "formSetQosBand",
      2073,
      "\x1B[0;32m",
      "wl.guest.down_speed",
      guest_down_speed);
  strcpy(guest_up_speed, guest_down_speed);
  set_wl_guest_qos_list(guest_up_speed, guest_down_speed);
  if ( CommitCfm(v5) )
  {
    snprintf(msg_info, 0x100u, "op=%d", 6);
    send_msg_to_netctrl(15, msg_info);
    v6 = 0;
  }
  else
  {
    v6 = 1;
  }
  sprintf(ret_buf, "{\"errCode\":%d}", v6);
  websTransfer(wp, ret_buf);
}
