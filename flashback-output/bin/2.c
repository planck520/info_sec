/* =====================================================
 *  Path 2
 *  vuln_type = CWE-120
 *  sink_func = memcpy
 *  source_func = recvfrom
 *  Hops:
 *    - memcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - sub_40F23C (arg=1, call_ea=0x40f8fc, func_ea=0x40f23c, label=needs_check)
 *        call: memcpy(&v32, (char *)v15 + HIBYTE(qword_497240) + 8, sizeof(v32));
 *    - recvfrom (arg=1, call_ea=0x40f7c8, func_ea=source, label=source)
 *        call: v16 = recvfrom(qword_497260, v15, 4096, 0, v39, &v31);
 * ===================================================== */


/* Function: sub_40F23C @ 0x40F23C */
int __fastcall sub_40F23C(int a1, int a2)
{
  int v3; // $a3
  int v4; // $v0
  int v5; // $s5
  const char *v6; // $s2
  char v7; // $v0
  int v8; // $v0
  int v9; // $a0
  int v10; // $s3
  bool v11; // dc
  int result; // $v0
  const char *v13; // $v0
  const char *v14; // $v0
  unsigned __int16 *v15; // $s1
  int v16; // $s2
  int v17; // $v0
  int v18; // $v1
  unsigned __int16 *v19; // $s2
  char v20; // $v1
  const char *v21; // $v0
  const char *v22; // $v1
  const char *v23; // $v0
  const char *v24; // $v0
  const char *v25; // $v0
  int v26; // $v0
  char v27; // $v0
  int v28; // $v0
  const char *v29; // [sp+20h] [-70h] BYREF
  int v30; // [sp+24h] [-6Ch] BYREF
  int v31; // [sp+28h] [-68h] BYREF
  int v32; // [sp+2Ch] [-64h] BYREF
  int v33; // [sp+30h] [-60h] BYREF
  int v34; // [sp+34h] [-5Ch]
  int v35; // [sp+38h] [-58h]
  int v36; // [sp+3Ch] [-54h]
  _DWORD v37[4]; // [sp+40h] [-50h] BYREF
  _BYTE v38[16]; // [sp+50h] [-40h] BYREF
  _DWORD v39[8]; // [sp+60h] [-30h] BYREF
  int v40; // [sp+80h] [-10h]
  const char *v41; // [sp+84h] [-Ch]
  const char *v42; // [sp+88h] [-8h]
  const char *v43; // [sp+8Ch] [-4h]

  v29 = "br0";
  HIDWORD(qword_497260) = -1;
  v30 = 0;
  LODWORD(qword_497260) = sub_405378(17, 1, 0);
  dword_4970B8 = (int)"=1:Df:AU:c+";
  if ( (sub_4693EC(a2, "DUAqfbc:w:I:s:", (char *)&qword_497260 + 4) & 0x80) != 0 )
    dword_49726C = 1000000 * sub_47470C(v31, 0, 1073, v3, &v29) + 500000;
  dword_4970BC &= 0x3Fu;
  v5 = *(_DWORD *)(a2 + 4 * optind);
  v4 = sub_4056A4("interface %s %%s", v29);
  byte_496B44 = 2;
  v6 = (const char *)v4;
  memset(v39, 0, sizeof(v39));
  sub_404E94(v39, v29);
  sub_405188(qword_497260, 35123, v39, v6, "not found", &v30);
  HIDWORD(qword_497238) = v39[4];
  sub_405074(qword_497260, 35091, v39, "SIOCGIFFLAGS");
  if ( (v39[4] & 1) == 0 )
    sub_4048A0(v6, "is down");
  if ( (v39[4] & 0x88) != 0 )
  {
    sub_40486C(v6, "is not ARPable");
    v7 = dword_4970BC;
    goto LABEL_28;
  }
  HIDWORD(qword_497230) = *(_DWORD *)(sub_474E2C(v5, 0) + 8);
  if ( v30 && !inet_aton(v30, &qword_497230) )
    sub_4048A0("invalid source address %s", v30);
  if ( (dword_4970BC & 3) != 2 )
    goto LABEL_14;
  if ( !(_DWORD)qword_497230 )
  {
    LODWORD(qword_497230) = HIDWORD(qword_497230);
LABEL_14:
    v8 = dword_4970BC & 1;
    goto LABEL_15;
  }
  v8 = dword_4970BC & 1;
LABEL_15:
  if ( !v8 || (_DWORD)qword_497230 )
  {
    v10 = sub_405378(2, 1, 0);
    sub_4751C4(v10);
    v35 = 0;
    v33 = 2;
    v36 = 0;
    if ( (_DWORD)qword_497230 )
    {
      v34 = qword_497230;
      sub_405334(v10, &v33, 16);
    }
    else
    {
      v31 = 16;
      HIWORD(v33) = 260;
      v34 = HIDWORD(qword_497230);
      if ( sub_475038(v10, 16) )
        sub_40628C("setsockopt(%s)", "SO_DONTROUTE");
      sub_474F0C(v10, &v33, 16);
      getsockname(v10, &v33, &v31);
      if ( (unsigned __int16)v33 != 2 )
        sub_4048A0("no IP address configured");
      LODWORD(qword_497230) = v34;
    }
    close(v10);
    v9 = qword_497260;
  }
  else
  {
    v9 = qword_497260;
  }
  LODWORD(qword_497238) = 101187601;
  sub_405334(v9, &qword_497238, 20);
  v31 = 20;
  getsockname(qword_497260, &qword_497238, &v31);
  if ( HIBYTE(qword_497240) )
  {
    memcpy(&MEMORY[0x49724C], &qword_497238, 20);
    memset(&qword_497258, -1, HIBYTE(MEMORY[0x497254]));
    if ( (dword_4970BC & 8) == 0 )
    {
      v13 = (const char *)inet_ntoa(HIDWORD(qword_497230));
      printf("ARPING to %s", v13);
      v14 = (const char *)inet_ntoa(qword_497230);
      printf(" from %s via %s\n", v14, v29);
    }
    sub_472910(2, sub_40EF50);
    sub_472910(14, sub_40F014);
    sub_40F014();
    v15 = (unsigned __int16 *)sub_405C98(4096);
    while ( 1 )
    {
      while ( 1 )
      {
        v31 = 20;
        v16 = recvfrom(qword_497260, v15, 4096, 0, v39, &v31);
        if ( v16 >= 0 )
          break;
        sub_40628C("recvfrom");
      }
      v40 = (int)v37;
      memset(v37, 0, sizeof(v37));
      sigaddset(v37, 14);
      sigaddset(v40, 2);
      sigprocmask(1, v40, v38);
      if ( BYTE2(v39[2]) < 3u )
      {
        v17 = v15[3];
        if ( v17 == 256 || v17 == 512 )
        {
          v18 = *v15;
          if ( (v18 == (unsigned __int16)(HIBYTE(LOWORD(v39[2])) | (LOWORD(v39[2]) << 8))
             || LOWORD(v39[2]) == 774 && v18 == 256)
            && v15[1] == 8
            && __PAIR64__(*((unsigned __int8 *)v15 + 5), *((unsigned __int8 *)v15 + 4)) == (HIBYTE(qword_497240)
                                                                                          | 0x400000000LL)
            && v16 >= 2 * (HIBYTE(qword_497240) + 8) )
          {
            v19 = v15 + 4;
            memcpy(&v32, (char *)v15 + HIBYTE(qword_497240) + 8, sizeof(v32));
            memcpy(&v33, &v15[*((unsigned __int8 *)v15 + 4) + 6], sizeof(v33));
            if ( HIDWORD(qword_497230) == v32 )
            {
              v40 = dword_4970BC;
              if ( (dword_4970BC & 1) != 0 )
              {
                if ( !memcmp(v15 + 4, &MEMORY[0x497244], HIBYTE(qword_497240))
                  || (_DWORD)qword_497230 && (_DWORD)qword_497230 != v33 )
                {
                  goto LABEL_77;
                }
                v20 = v40;
              }
              else
              {
                if ( (_DWORD)qword_497230 != v33
                  || memcmp(
                       (char *)v19 + *((unsigned __int8 *)v15 + 4) + 4,
                       &MEMORY[0x497244],
                       *((unsigned __int8 *)v15 + 4)) )
                {
                  goto LABEL_77;
                }
                v20 = v40;
              }
              if ( (v20 & 8) == 0 )
              {
                v21 = "Broad";
                v22 = "quest";
                if ( v15[3] == 0x200 )
                  v22 = "ply";
                if ( !BYTE2(v39[2]) )
                  v21 = "Uni";
                v43 = v22;
                v42 = v21;
                v41 = (const char *)inet_ntoa(v32);
                v23 = (const char *)ether_ntoa(v15 + 4);
                printf("%scast re%s from %s [%s]", v42, v43, v41, v23);
                v40 = 0;
                if ( v33 != (_DWORD)qword_497230 )
                {
                  v40 = 1;
                  v24 = (const char *)inet_ntoa(v33);
                  printf("for %s ", v24);
                }
                if ( memcmp(
                       (char *)v19 + *((unsigned __int8 *)v15 + 4) + 4,
                       &MEMORY[0x497244],
                       *((unsigned __int8 *)v15 + 4)) )
                {
                  if ( !v40 )
                    printf("for ");
                  v25 = (const char *)ether_ntoa(&v19[3 * *((unsigned __int8 *)v15 + 4) + 12]);
                  printf("[%s]", v25);
                }
                if ( dword_497268 )
                {
                  v26 = sub_4066B8();
                  printf(" %u.%03ums\n", (v26 - dword_497268) / 0x3E8u, (v26 - dword_497268) % 0x3E8u);
                }
                else
                {
                  puts(" UNSOLICITED?");
                }
                sub_405748();
              }
              ++dword_49727C;
              if ( BYTE2(v39[2]) )
                ++dword_497280;
              v27 = dword_4970BC;
              if ( v15[3] == 256 )
              {
                ++dword_497284;
                v27 = dword_4970BC;
              }
              v11 = (v27 & 0x10) == 0;
              v28 = v27 & 0x20;
              if ( !v11 )
                sub_40EF50();
              if ( !v28 )
              {
                memcpy(&qword_497258, v15 + 4, HIBYTE(qword_497240));
                dword_4970BC |= 0x40u;
              }
            }
          }
        }
      }
LABEL_77:
      sigprocmask(3, v38, 0);
    }
  }
  sub_40486C(v6, "is not ARPable (no ll address)");
  v7 = dword_4970BC;
LABEL_28:
  v11 = (v7 & 1) != 0;
  result = 2;
  if ( v11 )
    return 0;
  return result;
}
