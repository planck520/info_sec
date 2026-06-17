/* =====================================================
 *  Path 8
 *  vuln_type = CWE-120
 *  sink_func = strcpy
 *  source_func = websGetVar
 *  Hops:
 *    - strcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - sub_41E0A0 (arg=1, call_ea=0x41e594, func_ea=0x41e0a0, label=needs_check)
 *        call: strcpy(v69, v12);
 *    - websGetVar (arg=ret, call_ea=0x41e310, func_ea=source, label=source)
 *        call: v12 = (const char *)websGetVar(a1, "pppoeUser", &byte_431360);
 * ===================================================== */


/* Function: sub_41E0A0 @ 0x41E0A0 */
int __fastcall sub_41E0A0(int a1)
{
  int Var; // $v0
  int v3; // $s1
  int v4; // $v0
  int v5; // $s5
  _BYTE *v6; // $s3
  int v7; // $v0
  int v8; // $v0
  int v9; // $v0
  int v10; // $v0
  int v11; // $s2
  const char *v12; // $s4
  int v13; // $v0
  int v14; // $v0
  int v15; // $v0
  int v16; // $v0
  int v17; // $v0
  const char *v18; // $v0
  _BYTE *v19; // $v1
  int v20; // $a3
  int v21; // $a2
  int v22; // $a1
  int v23; // $a1
  int v24; // $a0
  const char *v25; // $v0
  _DWORD *v26; // $v1
  int v27; // $a3
  int v28; // $a2
  int v29; // $a1
  char *v30; // $s2
  char *v31; // $s7
  int v32; // $s6
  int v33; // $fp
  unsigned int i; // $s1
  int v35; // $v0
  int v36; // $v0
  unsigned int v37; // $v0
  int v38; // $s4
  int v39; // $fp
  int v40; // $s7
  int v41; // $s6
  int v42; // $s2
  int v43; // $s4
  int v44; // $fp
  int v45; // $s7
  int v46; // $s6
  int v47; // $s2
  const char *v48; // $s1
  int v49; // $v0
  int v50; // $s2
  int v51; // $v0
  int v52; // $s4
  int v53; // $s1
  int v54; // $v0
  int v55; // $s1
  int v56; // $v0
  _BYTE *v57; // $v0
  int v58; // $s1
  int v59; // $s0
  int result; // $v0
  char v61[64]; // [sp+18h] [-238h] BYREF
  _DWORD v62[3]; // [sp+58h] [-1F8h] BYREF
  char v63; // [sp+64h] [-1ECh]
  char v64; // [sp+68h] [-1E8h] BYREF
  int v65; // [sp+6Ch] [-1E4h]
  _BYTE v66[64]; // [sp+70h] [-1E0h] BYREF
  _BYTE v67[64]; // [sp+B0h] [-1A0h] BYREF
  _BYTE v68[64]; // [sp+F0h] [-160h] BYREF
  _BYTE v69[128]; // [sp+130h] [-120h] BYREF
  char v70[128]; // [sp+1B0h] [-A0h] BYREF
  int *v71; // [sp+230h] [-20h]
  int v72; // [sp+234h] [-1Ch]
  _BYTE *v73; // [sp+238h] [-18h]
  char *v74; // [sp+23Ch] [-14h]
  char *v75; // [sp+240h] [-10h]
  int v76; // [sp+244h] [-Ch]
  int v77; // [sp+248h] [-8h]

  memset(v61, 0, sizeof(v61));
  memset(v62, 0, sizeof(v62));
  v63 = 0;
  Var = websGetVar(a1, "proto", "1");
  v3 = atoi(Var);
  v4 = websGetVar(a1, "switchOpMode", &word_42F754);
  v5 = atoi(v4);
  v6 = (_BYTE *)websGetVar(a1, "opmode", &byte_431360);
  if ( !v3 )
  {
    strcpy(v61, "static");
    v7 = websGetVar(a1, "staticIp", &byte_431360);
    nvram_set("wan_ipaddr", v7);
    v8 = websGetVar(a1, "staticMask", &byte_431360);
    nvram_set("wan_netmask", v8);
    v9 = websGetVar(a1, "staticGw", &byte_431360);
    nvram_set("wan_gateway", v9);
    v10 = websGetVar(a1, "staticMtu", "1500");
    nvram_set("wan_mtu", v10);
    goto LABEL_46;
  }
  if ( v3 != 3 )
  {
    if ( v3 == 4 )
    {
      strcpy(v61, "pptp");
      v38 = websGetVar(a1, "pptpDomainFlag", &word_42F754);
      v39 = websGetVar(a1, "pptpServerDomain", &byte_431360);
      v40 = websGetVar(a1, "pptpServerIp", &byte_431360);
      v77 = websGetVar(a1, "pptpUser", &byte_431360);
      v76 = websGetVar(a1, "pptpPass", &byte_431360);
      v75 = (char *)websGetVar(a1, "pptpMppe", &word_42F754);
      v74 = (char *)websGetVar(a1, "pptpMppc", &word_42F754);
      v41 = websGetVar(a1, "pptpMtu", "1460");
      v42 = websGetVar(a1, "pptpMode", &word_42F754);
      v73 = (_BYTE *)websGetVar(a1, "pptpIp", &byte_431360);
      v72 = websGetVar(a1, "pptpMask", &byte_431360);
      v71 = (int *)websGetVar(a1, "pptpGw", &byte_431360);
      if ( atoi(v38) )
        nvram_set("wan_ppp_peer", v39);
      else
        nvram_set("wan_ppp_peer", v40);
      nvram_set("wan_pppoe_username", v77);
      nvram_set("wan_pppoe_passwd", v76);
      nvram_set("wan_ppp_auth", &word_42F754);
      nvram_set("wan_ppp_mppe", v75);
      nvram_set("wan_ppp_mppc", v74);
      nvram_set("wan_pptp_mtu", v41);
      nvram_set("wan_pptp_mru", v41);
      nvram_set("wan_ppp_alcp", &word_42F754);
      nvram_set("wan_lcp-echo", &word_42F754);
      nvram_set("wan_pppoe_idletime", &word_42F754);
      if ( !atoi(v42) )
      {
LABEL_34:
        nvram_set("x_DHCPClient", "1");
LABEL_36:
        nvram_set("wan_ipaddr", v73);
        nvram_set("wan_netmask", v72);
        nvram_set("wan_gateway", v71);
        goto LABEL_46;
      }
    }
    else
    {
      if ( v3 != 6 )
      {
        strcpy(v61, "dhcp");
        v48 = (const char *)websGetVar(a1, "hostName", &byte_431360);
        if ( *v48 )
        {
          nvram_set("wan_hostname", v48);
          doSystem("echo  '%s'  > /proc/sys/kernel/hostname", v48);
        }
        v49 = websGetVar(a1, "dhcpMtu", "1500");
        nvram_set("wan_mtu", v49);
        goto LABEL_46;
      }
      strcpy(v61, "l2tp");
      v43 = websGetVar(a1, "l2tpDomainFlag", &word_42F754);
      v44 = websGetVar(a1, "l2tpServerDomain", &byte_431360);
      v45 = websGetVar(a1, "l2tpServerIp", &byte_431360);
      v75 = (char *)websGetVar(a1, "l2tpUser", &byte_431360);
      v74 = (char *)websGetVar(a1, "l2tpPass", &byte_431360);
      v46 = websGetVar(a1, "l2tpMtu", "1460");
      v47 = websGetVar(a1, "l2tpMode", &word_42F754);
      v73 = (_BYTE *)websGetVar(a1, "l2tpIp", &byte_431360);
      v72 = websGetVar(a1, "l2tpMask", &byte_431360);
      v71 = (int *)websGetVar(a1, "l2tpGw", &byte_431360);
      if ( atoi(v43) )
        nvram_set("wan_ppp_peer", v44);
      else
        nvram_set("wan_ppp_peer", v45);
      nvram_set("pppDomainFlag", v43);
      nvram_set("wan_pppoe_username", v75);
      nvram_set("wan_pppoe_passwd", v74);
      nvram_set("wan_ppp_auth", &word_42F754);
      nvram_set("wan_ppp_mppe", &word_42F754);
      nvram_set("wan_l2tpd", &word_42F754);
      nvram_set("wan_l2tp_mtu", v46);
      nvram_set("wan_l2tp_mru", v46);
      nvram_set("wan_ppp_alcp", &word_42F754);
      nvram_set("wan_lcp-echo", &word_42F754);
      nvram_set("wan_pppoe_idletime", &word_42F754);
      if ( !atoi(v47) )
        goto LABEL_34;
    }
    nvram_set("x_DHCPClient", &word_42F754);
    goto LABEL_36;
  }
  strcpy(v61, "pppoe");
  v11 = websGetVar(a1, "pppoeSpecType", &word_42F754);
  nvram_set("wan_pppoe_spectype", v11);
  v12 = (const char *)websGetVar(a1, "pppoeUser", &byte_431360);
  nvram_set("wan_pppoe_username", v12);
  v13 = websGetVar(a1, "pppoePass", &byte_431360);
  nvram_set("wan_pppoe_passwd", v13);
  v14 = websGetVar(a1, "pppoeMtu", "1492");
  nvram_set("wan_pppoe_mtu", v14);
  v15 = websGetVar(a1, "pppoeServiceName", &byte_431360);
  nvram_set("wan_pppoe_service", v15);
  v16 = websGetVar(a1, "pppoeAcName", &byte_431360);
  nvram_set("wan_pppoe_ac", v16);
  v17 = atoi(v11);
  if ( v17 )
  {
    switch ( v17 )
    {
      case 1:
        sprintf(v67, "\\n\\r%s", v12);
        nvram_set("wan_pppoe_username_mm", v67);
        break;
      case 2:
        sprintf(v67, "^^%s", v12);
        nvram_set("wan_pppoe_username_mm", v67);
        break;
      case 3:
        v18 = "9012345678abcdeABCDEFGHIJKLMNfghijklmnUVWXYZxyzuvwopqrstOPQRST";
        v19 = v66;
        do
        {
          v20 = *((_DWORD *)v18 + 1);
          v21 = *((_DWORD *)v18 + 2);
          v22 = *((_DWORD *)v18 + 3);
          *(_DWORD *)v19 = *(_DWORD *)v18;
          *((_DWORD *)v19 + 1) = v20;
          *((_DWORD *)v19 + 2) = v21;
          *((_DWORD *)v19 + 3) = v22;
          v18 += 16;
          v19 += 16;
        }
        while ( v18 != "vwopqrstOPQRST" );
        v23 = *((_DWORD *)v18 + 1);
        v24 = *((_DWORD *)v18 + 2);
        *(_DWORD *)v19 = *(_DWORD *)v18;
        *((_DWORD *)v19 + 1) = v23;
        *((_DWORD *)v19 + 2) = v24;
        *((_WORD *)v19 + 6) = *((_WORD *)v18 + 6);
        v19[14] = v18[14];
        v25 = (const char *)&unk_42FBF0;
        v26 = v68;
        do
        {
          v27 = *((_DWORD *)v25 + 1);
          v28 = *((_DWORD *)v25 + 2);
          v29 = *((_DWORD *)v25 + 3);
          *v26 = *(_DWORD *)v25;
          v26[1] = v27;
          v26[2] = v28;
          v26[3] = v29;
          v25 += 16;
          v26 += 4;
        }
        while ( v25 != "tnt_network_x" );
        memset(v70, 0, sizeof(v70));
        v30 = v69;
        strcpy(v69, v12);
        v31 = v70;
        v71 = (int *)v68;
        v32 = 0;
        v33 = 0;
        v72 = 37;
        v73 = v69;
        v74 = &v64;
        v75 = v61;
        while ( v32 < (unsigned int)strlen(v73) )
        {
          v37 = strlen(v66);
          for ( i = 0; i < v37; ++i )
          {
            if ( *v30 == (char)v66[i] )
            {
              if ( v32 < 16 )
              {
                v35 = *v71;
              }
              else
              {
                div(v74, v32, 16);
                v35 = *(_DWORD *)&v75[4 * v65 + 216];
              }
              div(v74, ((3 * v72) ^ v33 ^ v35) + i, 62);
              v36 = v65;
              *v31 = v75[v65 + 88];
              v72 ^= v36 + 9433;
              break;
            }
          }
          v33 += 5;
          if ( !*v31 )
            *v31 = *v30;
          ++v32;
          ++v31;
          ++v30;
          ++v71;
        }
        sprintf(v67, "2:%s", v70);
        nvram_set("wan_pppoe_username_mm", v67);
        break;
    }
  }
  else
  {
    nvram_set("wan_pppoe_username_mm", v12);
  }
LABEL_46:
  nvram_set("wan_proto", v61);
  v50 = websGetVar(a1, "dnsMode", &word_42F754);
  v51 = atoi(v50);
  if ( v51 == 2 )
  {
    nvram_set("wan_dnsenable_x", &word_42F5AC);
  }
  else if ( v51 == 1 )
  {
    nvram_set("wan_dnsenable_x", &word_42F754);
  }
  else
  {
    nvram_set("wan_dnsenable_x", "1");
  }
  v52 = websGetVar(a1, "priDns", &byte_431360);
  v53 = websGetVar(a1, "secDns", &byte_431360);
  if ( atoi(v50) == 1 )
  {
    nvram_set("wan_dns1_x", v52);
    nvram_set("wan_dns2_x", v53);
  }
  if ( !*v6 || !strcmp(v6, "gw") || !strcmp(v6, "wisp") )
  {
    v54 = websGetVar(a1, "ttlWay", "-1");
    v55 = atoi(v54);
    if ( v55 != -1 )
    {
      v56 = nvram_get_int("mr_enable_x");
      if ( v55 || v56 != 1 )
        nvram_set_int("wan_ttl_fix", v55);
      else
        nvram_set("wan_ttl_fix", &word_42F5AC);
    }
    v57 = (_BYTE *)websGetVar(a1, "lcpEchoEnable", &byte_431360);
    if ( *v57 )
      nvram_set("wan_lcp_echo_enable", v57);
  }
  websGetVar(a1, "defaultMac", &byte_431360);
  v58 = websGetVar(a1, "cloneMac", &byte_431360);
  v59 = websGetVar(a1, "clone", &word_42F754);
  nvram_set("wan_clone_en", v59);
  if ( atoi(v59) )
  {
    mac_del_split(v58, v62);
    nvram_set("wan_hwaddr_x", v62);
  }
  else
  {
    nvram_set("wan_hwaddr_x", &byte_431360);
  }
  result = 1;
  if ( !v5 )
  {
    nvram_commit();
    notify_rc("restart_whole_wan");
    setResponse("30", "reserv");
    return 1;
  }
  return result;
}
