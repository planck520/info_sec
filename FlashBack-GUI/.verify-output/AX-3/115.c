/* =====================================================
 *  Path 115
 *  vuln_type = CWE-120
 *  sink_func = GetValue
 *  source_func = websGetVar
 *  Hops:
 *    - GetValue (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - formGetPPTPClient (arg=1, call_ea=0x4ab88, func_ea=0x4a9bc, label=needs_check)
 *        call: GetValue("vpn.cli.pptpMPPE", client_mppe);
 *    - formSetPPTPClient (arg=1, call_ea=0x4a5b4, func_ea=0x4a210, label=needs_check)
 *        call: SetValue("vpn.cli.pptpMPPE", vpn_type);
 *    - websGetVar (arg=ret, call_ea=0x4a42c, func_ea=source, label=source)
 *        call: vpn_type = websGetVar(wp, "clientMppe", "0");
 * ===================================================== */


/* Function: formGetPPTPClient @ 0x4A9BC */
void __fastcall formGetPPTPClient(webs_t wp, char_t *path, char_t *query)
{
  cJSON *Object; // r4
  cJSON *String; // r0
  cJSON *v5; // r0
  cJSON *v6; // r0
  cJSON *v7; // r0
  cJSON *v8; // r0
  cJSON *v9; // r0
  cJSON *v10; // r0
  cJSON *v11; // r0
  cJSON *v12; // r0
  cJSON *v13; // r0
  int v14; // r1
  int v15; // r2
  int v16; // r3
  int v17; // r0
  const char *v18; // r1
  char *v19; // r0
  const char *v20; // r1
  cJSON *v21; // r0
  cJSON *v22; // r0
  cJSON *v23; // r0
  cJSON *v24; // r2
  const char *v25; // r1
  cJSON *v26; // r0
  cJSON *v27; // r0
  cJSON *v28; // r0
  cJSON *v29; // r0
  cJSON *v30; // r0
  cJSON *v31; // r0
  cJSON *v32; // r0
  cJSON *v33; // r0
  cJSON *v34; // r0
  cJSON *v35; // r0
  int v36; // r1
  int v37; // r2
  const char *v38; // r1
  char *v39; // r0
  const char *v40; // r1
  cJSON *v41; // r0
  cJSON *v42; // r0
  cJSON *v43; // r0
  cJSON *v44; // r0
  cJSON *v45; // r0
  cJSON *v46; // r0
  char *v47; // r5
  char_t *fmt; // [sp+0h] [bp-1E8h]
  char_t *fmta; // [sp+0h] [bp-1E8h]
  char client_enable[4]; // [sp+28h] [bp-1C0h] BYREF
  char client_mppe[4]; // [sp+2Ch] [bp-1BCh] BYREF
  char client_mppeop[4]; // [sp+30h] [bp-1B8h] BYREF
  char status[4]; // [sp+34h] [bp-1B4h] BYREF
  char client_type[8]; // [sp+38h] [bp-1B0h] BYREF
  char client_wanid[8]; // [sp+40h] [bp-1A8h] BYREF
  char wanIp[32]; // [sp+48h] [bp-1A0h] BYREF
  char wanMask[32]; // [sp+68h] [bp-180h] BYREF
  char serverip[32]; // [sp+88h] [bp-160h] BYREF
  char vlan2ip[32]; // [sp+A8h] [bp-140h] BYREF
  char vlan2mask[32]; // [sp+C8h] [bp-120h] BYREF
  char client_seg[64]; // [sp+E8h] [bp-100h] BYREF
  char client_mask[64]; // [sp+128h] [bp-C0h] BYREF
  char ifaddr[64]; // [sp+168h] [bp-80h] BYREF
  char vpn_proc_name[64]; // [sp+1A8h] [bp-40h] BYREF
  char client_domain[128]; // [sp+1E8h] [bp+0h] BYREF
  char client_userName[256]; // [sp+268h] [bp+80h] BYREF
  char client_password[256]; // [sp+368h] [bp+180h] BYREF
  char mib_name[256]; // [sp+468h] [bp+280h] BYREF
  char mib_value[260]; // [sp+568h] [bp+380h] BYREF

  *(_DWORD *)client_enable = 0;
  memset(client_type, 0, sizeof(client_type));
  memset(client_domain, 0, sizeof(client_domain));
  *(_DWORD *)client_mppe = 0;
  *(_DWORD *)client_mppeop = 0;
  memset(client_wanid, 0, sizeof(client_wanid));
  memset(client_userName, 0, sizeof(client_userName));
  memset(client_password, 0, sizeof(client_password));
  memset(client_seg, 0, sizeof(client_seg));
  memset(client_mask, 0, sizeof(client_mask));
  *(_DWORD *)status = 0;
  memset(ifaddr, 0, sizeof(ifaddr));
  memset(vpn_proc_name, 0, sizeof(vpn_proc_name));
  memset(wanIp, 0, sizeof(wanIp));
  memset(wanMask, 0, sizeof(wanMask));
  memset(serverip, 0, sizeof(serverip));
  memset(vlan2ip, 0, sizeof(vlan2ip));
  memset(vlan2mask, 0, sizeof(vlan2mask));
  GetValue("vpn.cli.type", client_type);
  Object = cJSON_CreateObject();
  cgiGetWanIpAndMask(wanIp, wanMask, serverip, vlan2ip, vlan2mask);
  if ( !strcmp(client_type, "pptp") )
  {
    GetValue("vpn.cli.pptpEnable", client_enable);
    GetValue("vpn.cli.pptpwanid", client_wanid);
    GetValue("vpn.cli.pptpMPPE", client_mppe);
    GetValue("vpn.cli.pptpMPPE.op", client_mppeop);
    GetValue("vpn.cli.pptpPUN", client_userName);
    GetValue("vpn.cli.pptpPPW", client_password);
    GetValue("vpn.cli.pptpservIP", client_domain);
    GetValue("vpn.cli.pptpnetseg", client_seg);
    GetValue("vpn.cli.pptpnetmsk", client_mask);
    String = cJSON_CreateString(client_enable);
    cJSON_AddItemToObject(Object, "clientEn", String);
    v5 = cJSON_CreateString(client_type);
    cJSON_AddItemToObject(Object, "clientType", v5);
    v6 = cJSON_CreateString(client_domain);
    cJSON_AddItemToObject(Object, "domain", v6);
    v7 = cJSON_CreateString(client_mppe);
    cJSON_AddItemToObject(Object, "clientMppe", v7);
    v8 = cJSON_CreateString(client_mppeop);
    cJSON_AddItemToObject(Object, "clientMppeOp", v8);
    v9 = cJSON_CreateString(client_wanid);
    cJSON_AddItemToObject(Object, "clientWanid", v9);
    v10 = cJSON_CreateString(client_userName);
    cJSON_AddItemToObject(Object, "userName", v10);
    v11 = cJSON_CreateString(client_password);
    cJSON_AddItemToObject(Object, "password", v11);
    v12 = cJSON_CreateString(client_seg);
    cJSON_AddItemToObject(Object, "clientIp", v12);
    v13 = cJSON_CreateString(client_mask);
    cJSON_AddItemToObject(Object, "clientMask", v13);
    if ( ifaddrs_get_ifip("ppp0", ifaddr) >= 0 )
    {
      v19 = status;
      v20 = "1";
    }
    else
    {
      v17 = wanid_to_phy_port(1, v14, v15, v16);
      if ( get_port_link_status(v17) == 1 && !strcmp(client_enable, "1") )
        v18 = "2";
      else
        v18 = "0";
      strcpy(status, v18);
      v19 = ifaddr;
      v20 = "0.0.0.0";
    }
    strcpy(v19, v20);
    v21 = cJSON_CreateString(status);
    cJSON_AddItemToObject(Object, "pptpStatus", v21);
    v22 = cJSON_CreateString(ifaddr);
    cJSON_AddItemToObject(Object, "pptpIp", v22);
    v23 = cJSON_CreateString("0");
    cJSON_AddItemToObject(Object, "l2tpStatus", v23);
    v24 = cJSON_CreateString(&byte_794DF);
    v25 = "l2tpIp";
    goto LABEL_18;
  }
  if ( !strcmp(client_type, "l2tp") )
  {
    GetValue("vpn.cli.l2tpEnable", client_enable);
    GetValue("vpn.cli.l2tpwanid", client_wanid);
    GetValue("vpn.cli.pptpMPPE", client_mppe);
    GetValue("vpn.cli.pptpMPPE.op", client_mppeop);
    GetValue("vpn.cli.l2tpPUN", client_userName);
    GetValue("vpn.cli.l2tpPPW", client_password);
    GetValue("vpn.cli.l2tpservIP", client_domain);
    GetValue("vpn.cli.l2tpnetseg", client_seg);
    GetValue("vpn.cli.l2tpnetmsk", client_mask);
    v26 = cJSON_CreateString(client_enable);
    cJSON_AddItemToObject(Object, "clientEn", v26);
    v27 = cJSON_CreateString(client_type);
    cJSON_AddItemToObject(Object, "clientType", v27);
    v28 = cJSON_CreateString(client_domain);
    cJSON_AddItemToObject(Object, "domain", v28);
    v29 = cJSON_CreateString(client_mppe);
    cJSON_AddItemToObject(Object, "clientMppe", v29);
    v30 = cJSON_CreateString(client_mppeop);
    cJSON_AddItemToObject(Object, "clientMppeOp", v30);
    v31 = cJSON_CreateString(client_wanid);
    cJSON_AddItemToObject(Object, "clientWanid", v31);
    v32 = cJSON_CreateString(client_userName);
    cJSON_AddItemToObject(Object, "userName", v32);
    v33 = cJSON_CreateString(client_password);
    cJSON_AddItemToObject(Object, "password", v33);
    v34 = cJSON_CreateString(client_seg);
    cJSON_AddItemToObject(Object, "clientIp", v34);
    v35 = cJSON_CreateString(client_mask);
    cJSON_AddItemToObject(Object, "clientMask", v35);
    if ( ifaddrs_get_ifip("ppp45", ifaddr) >= 0 )
    {
      v39 = status;
      v40 = "1";
    }
    else
    {
      strcpy(vpn_proc_name, "xl2tpd-client");
      if ( proc_check_app(vpn_proc_name, v36, v37) )
        v38 = "2";
      else
        v38 = "0";
      strcpy(status, v38);
      v39 = ifaddr;
      v40 = "0.0.0.0";
    }
    strcpy(v39, v40);
    v41 = cJSON_CreateString(status);
    cJSON_AddItemToObject(Object, "l2tpStatus", v41);
    v42 = cJSON_CreateString(ifaddr);
    cJSON_AddItemToObject(Object, "l2tpIp", v42);
    v43 = cJSON_CreateString("0");
    cJSON_AddItemToObject(Object, "pptpStatus", v43);
    v24 = cJSON_CreateString(&byte_794DF);
    v25 = "pptpIp";
LABEL_18:
    cJSON_AddItemToObject(Object, v25, v24);
  }
  memset(mib_name, 0, sizeof(mib_name));
  memset(mib_value, 0, 0x100u);
  sprintf(mib_name, "wan%d.connecttype", 1);
  GetValue(mib_name, mib_value);
  v44 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "wanConnType", v44);
  memset(mib_name, 0, sizeof(mib_name));
  memset(mib_value, 0, 0x100u);
  sprintf(mib_name, "wan%d.ppoe.userid", 1);
  GetValue(mib_name, mib_value);
  v45 = cJSON_CreateString(mib_value);
  cJSON_AddItemToObject(Object, "wanUser", v45);
  v46 = cJSON_CreateString(wanIp);
  cJSON_AddItemToObject(Object, "wanIp", v46);
  v47 = cJSON_Print(Object);
  cJSON_Delete(Object);
  websWrite(wp, fmt);
  websWrite(wp, fmta);
  free(v47);
  websDone(wp, 200);
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
