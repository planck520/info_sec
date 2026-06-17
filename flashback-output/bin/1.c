/* =====================================================
 *  Path 1
 *  vuln_type = CWE-918
 *  sink_func = getaddrinfo
 *  source_func = getopt
 *  Hops:
 *    - getaddrinfo (arg=0, call_ea=None, func_ea=sink, label=sink)
 *    - sub_474BC4 (arg=0, call_ea=0x474d44, func_ea=0x474bc4, label=needs_check)
 *        call: if ( getaddrinfo(v12, 0, v21, &v19) || (v15 = v19) == 0 )
 *    - sub_474E24 (arg=0, call_ea=0x474e24, func_ea=0x474e24, label=certain)
 *        call: return sub_474BC4(a1, a2, 6);
 *    - sub_4750D8 (arg=0, call_ea=0x475104, func_ea=0x4750d8, label=needs_check)
 *        call: v4 = sub_474E24(a1, a2);
 *    - sub_4751B4 (arg=0, call_ea=0x4751b4, func_ea=0x4751b4, label=certain)
 *        call: return sub_4750D8(a1, a2, 2);
 *    - sub_414954 (arg=0, call_ea=0x414bc8, func_ea=0x414954, label=needs_check)
 *        call: v36 = sub_4751B4(*v17, v4);
 *    - getopt (arg=1, call_ea=0x414afc, func_ea=source, label=source)
 *        call: while ( 1 )
 * ===================================================== */


/* Function: sub_474BC4 @ 0x474BC4 */
int __fastcall sub_474BC4(const char *a1, __int16 a2, int a3)
{
  int v5; // $v0
  int v7; // $s3
  int v8; // $v0
  int v9; // $a0
  int v10; // $a3
  unsigned int v11; // $v0
  const char *v12; // $s3
  int v13; // $a0
  int v14; // $s0
  int v15; // $s3
  _DWORD *v16; // $v0
  int v18; // [sp+10h] [+10h] BYREF
  int v19; // [sp+18h] [+18h] BYREF
  int v20; // [sp+1Ch] [+1Ch] BYREF
  _DWORD v21[9]; // [sp+20h] [+20h] BYREF

  v19 = 0;
  v5 = strrchr(a1, 58);
  v7 = v5;
  if ( !v5 )
  {
    v12 = a1;
    goto LABEL_7;
  }
  v8 = sub_472550(&v18, a1, v5 - (_DWORD)a1 + 1);
  v9 = v7 + 1;
  v12 = (const char *)v8;
  v11 = sub_406EBC(v9, 0, 10, v10, 0x49EB40u);
  if ( !*(_DWORD *)dword_497094 )
  {
    a2 = v11;
    if ( v11 < 0x10000 )
    {
LABEL_7:
      if ( inet_aton(v12, &v20) )
      {
        v14 = sub_405E70(20);
        *(_DWORD *)v14 = 16;
        *(_WORD *)(v14 + 4) = 2;
        *(_DWORD *)(v14 + 8) = v20;
      }
      else
      {
        memset(v21, 0, 32);
        v21[2] = 2;
        v21[0] = a3 & 0xFFFFFFFD;
        v21[1] = 2;
        if ( getaddrinfo(v12, 0, v21, &v19) || (v15 = v19) == 0 )
        {
          sub_40486C("bad address '%s'", a1);
          v14 = 0;
          if ( (a3 & 2) != 0 )
            goto LABEL_13;
          goto LABEL_15;
        }
        v16 = (_DWORD *)sub_405C98(*(_DWORD *)(v19 + 16) + 4);
        *v16 = *(_DWORD *)(v15 + 16);
        v14 = (int)v16;
        memcpy(v16 + 1, *(_DWORD *)(v15 + 20), *(_DWORD *)(v15 + 16));
      }
      sub_474A48(v14 + 4, (unsigned __int16)HIBYTE(a2) | (unsigned __int16)(a2 << 8));
LABEL_15:
      if ( v19 )
        freeaddrinfo();
      return v14;
    }
  }
  sub_40486C("bad port spec '%s'", a1);
  v14 = 0;
  if ( (a3 & 2) != 0 )
LABEL_13:
    sub_4048D8(v13);
  return v14;
}


/* Function: sub_474E24 @ 0x474E24 */
int __fastcall sub_474E24(const char *a1, __int16 a2)
{
  return sub_474BC4(a1, a2, 6);
}


/* Function: sub_4750D8 @ 0x4750D8 */
int __fastcall sub_4750D8(const char *a1, __int16 a2, int a3)
{
  int v4; // $v0
  int v5; // $a0
  int v6; // $v0
  int v7; // $a0
  int *v9; // [sp+18h] [-10h] BYREF
  int v10; // [sp+20h] [-8h]

  if ( a1 && *a1 )
  {
    v10 = a3;
    v4 = sub_474E24(a1, a2);
    v5 = *(unsigned __int16 *)(v4 + 4);
    v9 = (int *)v4;
    v6 = sub_405378(v5, v10, 0);
    v7 = v6;
  }
  else
  {
    v10 = sub_474B38(&v9, 0, a3);
    sub_474A48(v9 + 1, (unsigned __int16)HIBYTE(a2) | (unsigned __int16)(a2 << 8));
    v6 = v10;
    v7 = v10;
  }
  v10 = v6;
  sub_475050(v7);
  sub_405334(v10, (int)(v9 + 1), *v9);
  free(v9);
  return v10;
}


/* Function: sub_4751B4 @ 0x4751B4 */
int __fastcall sub_4751B4(const char *a1, __int16 a2)
{
  return sub_4750D8(a1, a2, 2);
}


/* Function: sub_414954 @ 0x414954 */
void __fastcall __noreturn sub_414954(int a1, int a2)
{
  int v4; // $s4
  int v5; // $a0
  int v6; // $a1
  _DWORD *v7; // $v0
  int v8; // $v1
  int v9; // $v0
  int v10; // $a2
  int v11; // $a3
  int v12; // $s1
  int v13; // $s0
  BOOL v14; // $s0
  bool v15; // dc
  int v16; // $v0
  _DWORD *v17; // $s2
  int v18; // $a0
  int v19; // $s0
  int v20; // $v0
  int v21; // $v0
  _BYTE *v22; // $v0
  int v23; // $a1
  int v24; // $fp
  int v25; // $s4
  int v26; // $s7
  int v27; // $a2
  int v28; // $a0
  _DWORD v29[32]; // [sp+20h] [-128h] BYREF
  _BYTE v30[128]; // [sp+A0h] [-A8h] BYREF
  int v31; // [sp+120h] [-28h]
  const char **v32; // [sp+124h] [-24h]
  unsigned int v33; // [sp+128h] [-20h]
  unsigned int v34; // [sp+12Ch] [-1Ch]
  int v35; // [sp+130h] [-18h]
  int v36; // [sp+134h] [-14h]
  int v37; // [sp+138h] [-10h]
  int v38; // [sp+13Ch] [-Ch]
  int v39; // [sp+140h] [-8h]

  v32 = 0;
  v38 = 0;
  v35 = 0;
  v34 = 0;
  v4 = 0;
  v31 = 0;
  while ( 1 )
  {
    v9 = getopt(a1, a2, "lp:w:i:f:e:");
    if ( v9 <= 0 )
      break;
    v5 = v34;
    if ( v9 == 108 )
    {
      ++v34;
    }
    else
    {
      v6 = 112;
      switch ( v9 )
      {
        case 'p':
          v4 = sub_474E3C(optarg, "tcp", 0);
          break;
        case 'w':
          v35 = sub_474704(optarg);
          break;
        case 'i':
          v38 = sub_474704(optarg);
          break;
        case 'f':
          v31 = sub_405028(optarg, 2, v10, v11);
          break;
        case 'e':
          v5 = 2 - optind;
          if ( a1 < optind )
            goto LABEL_27;
          v32 = (const char **)sub_405E70(4 * (v5 + a1));
          v7 = v32 + 1;
          *v32 = (const char *)optarg;
          while ( 1 )
          {
            v8 = optind;
            if ( optind >= a1 )
              break;
            *v7 = *(_DWORD *)(a2 + 4 * optind);
            optind = v8 + 1;
            ++v7;
          }
          break;
        default:
          goto LABEL_27;
      }
    }
  }
  v6 = v34;
  v12 = optind;
  v13 = a1 - optind;
  if ( v34 )
  {
    if ( v31 )
      goto LABEL_27;
    v14 = v13 < 2;
  }
  else
  {
    if ( v31 )
    {
      if ( v13 )
LABEL_27:
        sub_403BFC(v5, v6, v10, v11);
      v16 = v35;
LABEL_29:
      if ( v16 )
      {
        signal(14, sub_414EF8);
        alarm(v35);
      }
      if ( v31 )
        goto LABEL_41;
      v17 = (_DWORD *)(a2 + 4 * v12);
      if ( !v34 )
      {
        v18 = v17[1];
        v19 = *v17;
        v20 = 0;
        if ( v18 )
          v20 = sub_474E3C(v18, "tcp", 0);
        v31 = sub_475058(v19, v20);
        goto LABEL_41;
      }
      v36 = sub_4751B4(*v17, v4);
      sub_4052F0(v36, v34);
      sub_404EA8(v36);
      while ( 1 )
      {
        v31 = accept(v36, 0, 0);
        if ( v31 < 0 )
          sub_40631C("accept");
        v5 = (int)v32;
        if ( !v32 )
          close(v36);
LABEL_41:
        if ( v35 )
          alarm(0);
        if ( !v32 )
        {
          v22 = v29;
          v29[0] = 0;
          while ( 1 )
          {
            v22 += 4;
            if ( v22 == v30 )
              break;
            *(_DWORD *)v22 = 0;
          }
          v23 = v31;
          v29[(unsigned int)v31 >> 5] |= 1 << v31;
          v24 = v38;
          v29[0] |= 1u;
          v25 = v23 + 1;
          v26 = v23;
          while ( 1 )
          {
            memcpy(v30, v29, sizeof(v30));
            if ( select(v25, v30, 0, 0, 0) < 0 )
              break;
            v33 = 0;
            v37 = v29[0];
            while ( 1 )
            {
              if ( (((int)v29[(v33 >> 5) + 32] >> v33) & 1) != 0 )
              {
                v27 = sub_4063B0(v33, &qword_497230, 4097);
                if ( v33 == v26 )
                {
                  v28 = 1;
                  if ( v27 <= 0 )
                    exit(0);
                }
                else
                {
                  v28 = v26;
                  if ( v27 <= 0 )
                  {
                    v39 = v27;
                    shutdown(v26, 1);
                    v27 = v39;
                    v28 = v26;
                    v37 &= ~1u;
                  }
                }
                sub_405890(v28, &qword_497230, v27);
                if ( v24 )
                  sleep(v24);
              }
              if ( v33 == v26 )
                break;
              v33 = v26;
            }
            v29[0] = v37;
          }
          sub_40631C("select");
        }
        if ( v34 < 2 )
          goto LABEL_49;
        v21 = vfork(v5);
        if ( v21 < 0 )
          sub_40631C("vfork");
        if ( !v21 )
        {
LABEL_49:
          sub_405978(v31, 0);
          sub_40592C(0, 1);
          execvp(*v32, v32);
          sub_40631C("can't execute '%s'", *v32);
        }
        signal(18, 1);
        close(v31);
      }
    }
    v15 = v13 == 0;
    v14 = v13 < 3;
    if ( v15 )
      goto LABEL_27;
  }
  v16 = v35;
  if ( !v14 )
    goto LABEL_27;
  goto LABEL_29;
}
