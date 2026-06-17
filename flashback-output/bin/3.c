/* =====================================================
 *  Path 3
 *  vuln_type = CWE-120
 *  sink_func = memcpy
 *  source_func = sscanf
 *  Hops:
 *    - memcpy (arg=1, call_ea=None, func_ea=sink, label=sink)
 *    - sub_405D38 (arg=1, call_ea=0x405da8, func_ea=0x405d38, label=certain)
 *        call: return memcpy(v6, a1, v8);
 *    - sub_440874 (arg=0, call_ea=0x440d38, func_ea=0x440874, label=needs_check)
 *        call: dword_497270 = sub_405D38(v58 + 1, v33 - (v58 + 1));
 *    - sscanf (arg=0, call_ea=0x440ca0, func_ea=source, label=source)
 *        call: v30 = sscanf(v21, "@%u,%u-%u", &MEMORY[0x49725C], &qword_497260, &MEMORY[0x497264]);
 * ===================================================== */


/* Function: sub_405D38 @ 0x405D38 */
int __fastcall sub_405D38(unsigned __int8 *a1, int a2)
{
  unsigned __int8 *v3; // $v1
  int i; // $v0
  int v6; // $v0
  int v8; // [sp+18h] [-8h]

  v3 = a1;
  for ( i = a2; i; --i )
  {
    if ( !*v3++ )
      break;
  }
  v8 = a2 - i;
  v6 = sub_405C98(a2 - i + 1);
  *(_BYTE *)(v6 + v8) = 0;
  return memcpy(v6, a1, v8);
}


/* Function: sub_440874 @ 0x440874 */
int __fastcall sub_440874(const char *a1, int a2, int a3)
{
  int v6; // $v0
  int v7; // $s1
  int result; // $v0
  _BYTE *v9; // $s1
  int v10; // $v0
  int v11; // $v0
  int v12; // $v0
  int v13; // $s5
  int v14; // $v0
  int v15; // $v1
  int *v16; // $s1
  int v17; // $v0
  int i; // $a0
  _BYTE *v19; // $a2
  int v20; // $v0
  unsigned __int8 *v21; // $a2
  int v22; // $v0
  int v23; // $v0
  int v24; // $v0
  int v25; // $a2
  int v26; // $v0
  _BYTE *v27; // $v1
  int v28; // $a2
  _BYTE *v29; // $a3
  int v30; // $v0
  int v31; // $v0
  const char *v32; // $a1
  int v33; // $v0
  _BYTE *v34; // $a2
  int v35; // $a1
  int v36; // $v1
  _DWORD *j; // $s3
  int v38; // $v0
  int v39; // $v0
  int v40; // $s3
  const char *v41; // $s3
  int v42; // $a1
  int v43; // $v0
  _BYTE *v44; // $v0
  __int64 v45; // $v0
  int v46; // $a0
  int v47; // [sp+28h] [-30h] BYREF
  int v48; // [sp+2Ch] [-2Ch] BYREF
  int v49; // [sp+30h] [-28h] BYREF
  int v50; // [sp+34h] [-24h]
  _BYTE *v51; // [sp+38h] [-20h] BYREF
  const char *v52; // [sp+3Ch] [-1Ch]
  int v53; // [sp+40h] [-18h]
  _BYTE *v54; // [sp+44h] [-14h]
  int v55; // [sp+48h] [-10h]
  int *v56; // [sp+4Ch] [-Ch]
  _BYTE *v57; // [sp+50h] [-8h]
  int v58; // [sp+54h] [-4h]

  v7 = strlen(a2);
  v6 = sub_404554(a2);
  result = strcmp(v6, "device");
  if ( !result )
    return result;
  v9 = (_BYTE *)(a2 + v7);
  v47 = -1;
  if ( !a3 )
  {
    strcpy(v9, "/dev");
    v10 = sub_406508(a2, v9 + 1, 127);
    *v9 = 0;
    if ( v10 > 0 )
    {
      if ( sscanf(v9 + 1, "%u:%u", &v47, &v48) == 2 )
      {
        if ( (_BYTE)qword_497238 )
          sub_40486C("dev %u,%u", v47, v48);
      }
      else
      {
        v47 = -1;
      }
    }
  }
  if ( !a1 )
  {
    strcpy(v9, "/uevent");
    v11 = sub_406508(a2, v9 + 1, 127);
    if ( v11 < 0 )
      v11 = 0;
    *v9 = 0;
    v9[v11 + 1] = 0;
    v12 = strstr(v9 + 1, "\nDEVNAME=");
    if ( v12 )
    {
      a1 = (const char *)(v12 + 9);
      *(_BYTE *)strchrnul(v12 + 9, 10) = 0;
    }
    else
    {
      a1 = (const char *)sub_404554(a2);
    }
  }
  if ( strstr(a2, "/block/") || MEMORY[0x49723C] && sub_404294(MEMORY[0x49723C], "block") )
    v13 = 24576;
  else
    v13 = 0x2000;
  qword_497250 = 0;
  while ( 1 )
  {
LABEL_20:
    v14 = qword_497248;
LABEL_21:
    while ( 2 )
    {
      if ( v14 )
      {
        v15 = MEMORY[0x49724C];
      }
      else
      {
        if ( MEMORY[0x497244] )
        {
          qword_497248 = sub_46F618(MEMORY[0x497244], sub_474320);
          MEMORY[0x497244] = 0;
        }
        v15 = MEMORY[0x49724C];
      }
      if ( v15 )
      {
        v16 = *(int **)(v15 + 4 * qword_497250);
        if ( v16 )
        {
          ++qword_497250;
          goto LABEL_64;
        }
        sub_44068C();
        v17 = qword_497248;
      }
      else
      {
        sub_4406DC();
        v17 = qword_497248;
      }
      v16 = &MEMORY[0x497254];
      if ( !v17 )
        goto LABEL_64;
      for ( i = qword_497248; sub_46F184(i, &v51, 459524, "# \t"); i = qword_497248 )
      {
        v56 = &dword_49729C;
        v19 = &v51[*v51 == 0x2D];
        LOBYTE(MEMORY[0x497254]) = *v51 == 0x2D;
        while ( 1 )
        {
          v58 = (int)v19;
          v20 = strchr(v19, 61);
          v21 = (unsigned __int8 *)v58;
          if ( !v20 )
            break;
          v57 = (_BYTE *)v20;
          v22 = sub_468714(v58);
          v55 = v22;
          v21 = (unsigned __int8 *)v58;
          if ( (_BYTE *)v22 != v57 )
            break;
          v23 = strchr(v22, 59);
          v21 = (unsigned __int8 *)v58;
          if ( !v23 )
            break;
          v57 = (_BYTE *)v23;
          v24 = sub_405E70(40);
          v25 = v58;
          *v56 = v24;
          v56 = (int *)v24;
          v26 = sub_405D38(v25, v55 - v25);
          v56[1] = v26;
          v27 = v57;
          v28 = v55;
          *v57 = 0;
          v57 = v27;
          sub_4757DC(v56 + 2, v28 + 1, 1);
          v19 = v57 + 1;
          *v57 = 59;
        }
        v29 = (_BYTE *)*v21;
        if ( v29 == (_BYTE *)64 )
        {
          v30 = sscanf(v21, "@%u,%u-%u", &MEMORY[0x49725C], &qword_497260, &MEMORY[0x497264]);
          if ( v30 < 2 )
          {
            v31 = qword_497248;
LABEL_44:
            sub_40486C("bad @maj,min on line %d", *(_DWORD *)(v31 + 24));
            goto LABEL_59;
          }
          if ( MEMORY[0x49725C] < 0 )
          {
            v31 = qword_497248;
            goto LABEL_44;
          }
          v32 = v52;
          if ( v30 != 2 )
            goto LABEL_53;
          MEMORY[0x497264] = qword_497260;
        }
        else
        {
          v58 = (int)v21;
          v57 = v29;
          v33 = strchr(v21, 61);
          v34 = (_BYTE *)v58;
          if ( v57 == (_BYTE *)36 )
          {
            if ( !v33 )
            {
              sub_40486C("bad $envvar=regex on line %d", *(_DWORD *)(qword_497248 + 24));
              goto LABEL_59;
            }
            v57 = (_BYTE *)v33;
            dword_497270 = sub_405D38(v58 + 1, v33 - (v58 + 1));
            v34 = v57 + 1;
          }
          sub_4757DC(&dword_49727C, v34, 1);
          BYTE1(MEMORY[0x497254]) = 1;
        }
        v32 = v52;
LABEL_53:
        if ( sub_475894(&dword_497268, v32, 1) )
        {
          qword_497258 = sub_46F66C(v53, qword_497258);
          if ( !v54 )
            goto LABEL_62;
          v35 = (unsigned __int8)*v54;
          if ( !*v54 )
            goto LABEL_62;
          v57 = v54;
          if ( strchr("$@*", v35) )
          {
            dword_497278 = sub_405BA0(v57);
            goto LABEL_62;
          }
          sub_40486C("bad line %u", *(_DWORD *)(qword_497248 + 24));
        }
        else
        {
          sub_40486C("unknown user/group '%s' on line %d", v52, *(_DWORD *)(qword_497248 + 24));
        }
LABEL_59:
        sub_4406DC();
      }
      sub_46F590(qword_497248);
      qword_497248 = 0;
LABEL_62:
      if ( MEMORY[0x49724C] )
      {
        v16 = (int *)sub_405CEC(&MEMORY[0x497254], 76);
        MEMORY[0x49724C] = sub_47569C(MEMORY[0x49724C], 1028, qword_497250);
        v36 = qword_497250 + 1;
        *(_DWORD *)(MEMORY[0x49724C] + 4 * qword_497250) = v16;
        qword_497250 = v36;
      }
LABEL_64:
      for ( j = (_DWORD *)v16[18]; j; j = (_DWORD *)*j )
      {
        v38 = getenv(j[1]);
        if ( !v38 || regexec(j + 2, v38, 0, 0, 0) )
          goto LABEL_20;
      }
      v39 = v16[2];
      if ( v39 >= 0 )
      {
        if ( v47 != v39 )
        {
          v14 = qword_497248;
          continue;
        }
        if ( v48 < v16[3] )
        {
          v14 = qword_497248;
          continue;
        }
        if ( v16[4] < v48 )
        {
          v14 = qword_497248;
          continue;
        }
        v49 = 0;
        v50 = 0;
        goto LABEL_84;
      }
      break;
    }
    v46 = v16[7];
    v40 = (int)a1;
    if ( v46 )
    {
      v40 = getenv(v46);
      if ( !v40 )
        continue;
    }
    if ( !*((_BYTE *)v16 + 1) )
      break;
    if ( !regexec(v16 + 10, v40, 1, &v49, 0) )
    {
      if ( v49 )
      {
        v14 = qword_497248;
        goto LABEL_21;
      }
      if ( v50 == strlen(v40) )
        break;
    }
  }
LABEL_84:
  if ( (char)qword_497238 >= 2 )
  {
    v42 = -1;
    if ( qword_497248 )
      v42 = *(_DWORD *)(qword_497248 + 24);
    sub_40486C("rule matched, line %d", v42);
    v41 = (const char *)v16[9];
  }
  else
  {
    v41 = (const char *)v16[9];
  }
  if ( v41 )
  {
    v43 = *(unsigned __int8 *)v41;
    switch ( v43 )
    {
      case '@':
        if ( a3 )
          goto LABEL_118;
LABEL_99:
        ++v41;
        break;
      case '$':
        if ( a3 == 1 )
          ++v41;
        else
          v41 = 0;
        break;
      case '*':
        goto LABEL_99;
      default:
        v41 = 0;
        break;
    }
  }
  if ( !a3 && v47 >= 0 )
  {
    v44 = (_BYTE *)strrchr(a1, 47);
    if ( v44 )
    {
      *v44 = 0;
      v57 = v44;
      umask(18);
      sub_46ED28(a1, 493, 4);
      umask(0);
      *v57 = 47;
    }
    if ( (_BYTE)qword_497238 )
      sub_40486C("mknod %s (%d,%d) %o %u:%u", a1, v47, v48, v13 | v16[1], v16[5], v16[6]);
    v58 = v13 | v16[1];
    v45 = sub_46EF98(v47, v48);
    if ( mknod(a1, v58, v45, HIDWORD(v45)) && *(_DWORD *)dword_497094 != 17 )
      sub_40628C("can't create '%s'", a1);
    chmod(a1, v16[1]);
    chown(a1, v16[5], v16[6]);
    if ( v47 == qword_497230 && v48 == MEMORY[0x497234] )
      symlink(a1, "root");
  }
  if ( v41 )
  {
    v55 = sub_4056A4("%s=%s", "MDEV");
    putenv(v55);
    if ( (_BYTE)qword_497238 )
      sub_40486C("running: %s", v41);
    if ( system(v41) == -1 )
      sub_40628C("can't run '%s'", v41);
    sub_405E34(v55);
  }
LABEL_118:
  if ( a3 != 1 )
  {
LABEL_124:
    result = *(unsigned __int8 *)v16;
    goto LABEL_125;
  }
  if ( v47 >= -1 )
  {
    if ( (_BYTE)qword_497238 )
      sub_40486C("unlink: %s", a1);
    unlink(a1);
    goto LABEL_124;
  }
  result = *(unsigned __int8 *)v16;
LABEL_125:
  if ( result )
  {
    v14 = qword_497248;
    goto LABEL_21;
  }
  return result;
}
