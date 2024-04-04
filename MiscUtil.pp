{ Copyright (C) 2024 by Bill Stewart (bstewart at iname.com)

  This program is free software: you can redistribute it and/or modify it under
  the terms of the GNU General Public License as published by the Free Software
  Foundation, either version 3 of the License, or (at your option) any later
  version.

  This program is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
  FOR A PARTICULAR PURPOSE. See the GNU General Public License for more
  details.

  You should have received a copy of the GNU General Public License
  along with this program. If not, see https://www.gnu.org/licenses/.

}

unit MiscUtil;

{$MODE OBJFPC}
{$MODESWITCH UNICODESTRINGS}

interface

type
  COMPUTER_NAME_FORMAT                    = (
    ComputerNameNetBIOS                   = 0,
    ComputerNameDnsHostname               = 1,
    ComputerNameDnsDomain                 = 2,
    ComputerNameDnsFullyQualified         = 3,
    ComputerNamePhysicalNetBIOS           = 4,
    ComputerNamePhysicalDnsHostname       = 5,
    ComputerNamePhysicalDnsDomain         = 6,
    ComputerNamePhysicalDnsFullyQualified = 7,
    ComputerNameMax                       = 8);
  TStringArray = array of string;

function Trim(S: string): string;

procedure StrSplit(S, Delim: string; var Dest: TStringArray);

function GetComputerName(const NameFormat: COMPUTER_NAME_FORMAT;
  out Name: string): DWORD;

function GetFileVersion(const FileName: string): string;

implementation

uses
  windows;

function GetComputerNameExW(NameType: COMPUTER_NAME_FORMAT;
  lpBuffer: LPWSTR;
  var nSize: DWORD): BOOL;
  stdcall; external 'kernel32.dll';

function Trim(S: string): string;
var
  I, J: Integer;
begin
  I := Length(S);
  if I > 0 then
  begin
    J := I;
    while (J > 0) and ((S[J] = ' ') or (S[J] = #9)) do
      Dec(J);
    if J <> I then
      SetLength(S, J);
  end;
  result := S;
end;

// Returns the number of times Substring appears in S
function CountSubstring(const Substring, S: string): LongInt;
var
  P: LongInt;
begin
  result := 0;
  P := Pos(Substring, S, 1);
  while P <> 0 do
  begin
    Inc(result);
    P := Pos(Substring, S, P + Length(Substring));
  end;
end;

procedure StrSplit(S, Delim: string; var Dest: TStringArray);
var
  I, P: Integer;
begin
  I := CountSubstring(Delim, S);
  // If no delimiters, Dest is a single-element array
  if I = 0 then
  begin
    SetLength(Dest, 1);
    Dest[0] := S;
    exit;
  end;
  SetLength(Dest, I + 1);
  for I := 0 to Length(Dest) - 1 do
  begin
    P := Pos(Delim, S);
    if P > 0 then
    begin
      Dest[I] := Copy(S, 1, P - 1);
      Delete(S, 1, P + Length(Delim) - 1);
    end
    else
      Dest[I] := S;
  end;
end;

function IntToStr(const I: LongInt): string;
begin
  Str(I, result);
end;

function GetFileVersion(const FileName: string): string;
var
  VerInfoSize, Handle: DWORD;
  pBuffer: Pointer;
  pFileInfo: ^VS_FIXEDFILEINFO;
  Len: UINT;
begin
  result := '';
  VerInfoSize := GetFileVersionInfoSizeW(PChar(FileName),  // LPCWSTR lptstrFilename
    Handle);                                               // LPDWORD lpdwHandle
  if VerInfoSize > 0 then
  begin
    GetMem(pBuffer, VerInfoSize);
    if GetFileVersionInfoW(PChar(FileName),  // LPCWSTR lptstrFilename
      Handle,                                // DWORD   dwHandle
      VerInfoSize,                           // DWORD   dwLen
      pBuffer) then                          // LPVOID  lpData
    begin
      if VerQueryValueW(pBuffer,  // LPCVOID pBlock
        '\',                      // LPCWSTR lpSubBlock
        pFileInfo,                // LPVOID  *lplpBuffer
        Len) then                 // PUINT   puLen
      begin
        with pFileInfo^ do
        begin
          result := IntToStr(HiWord(dwFileVersionMS)) + '.' +
            IntToStr(LoWord(dwFileVersionMS)) + '.' +
            IntToStr(HiWord(dwFileVersionLS));
          // LoWord(dwFileVersionLS) intentionally omitted
        end;
      end;
    end;
    FreeMem(pBuffer);
  end;
end;

function GetComputerName(const NameFormat: COMPUTER_NAME_FORMAT;
  out Name: string): DWORD;
var
  NumChars, BufSize: DWORD;
  pName: PChar;
begin
  NumChars := 0;
  // Fails and updates nSize with # characters needed, including null
  GetComputerNameExW(NameFormat,  // COMPUTER_NAME_FORMAT NameType
    nil,                          // LPWSTR               lpBuffer
    NumChars);                    // LPDWORD              nSize
  result := GetLastError();
  // If GetLastError() doesn't return ERROR_MORE_DATA, something else wrong
  if result <> ERROR_MORE_DATA then
    exit;
  BufSize := NumChars * SizeOf(Char);
  GetMem(pName, BufSize);
  if GetComputerNameExW(NameFormat,  // COMPUTER_NAME_FORMAT NameType
    pName,                           // LPWSTR               lpBuffer
    NumChars) then                   // LPDWORD              nSize
  begin
    Name := string(pName);
    result := ERROR_SUCCESS;
  end
  else
    result := GetLastError();
  FreeMem(pName);
end;

begin
end.
