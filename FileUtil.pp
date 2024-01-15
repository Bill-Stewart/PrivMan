{ Copyright (C) 2024 by Bill Stewart (bstewart at iname.com)

  This program is free software; you can redistribute it and/or modify it under
  the terms of the GNU Lesser General Public License as published by the Free
  Software Foundation; either version 3 of the License, or (at your option) any
  later version.

  This program is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
  FOR A PARTICULAR PURPOSE. See the GNU General Lesser Public License for more
  details.

  You should have received a copy of the GNU Lesser General Public License
  along with this program. If not, see https://www.gnu.org/licenses/.

}

unit FileUtil;

{$MODE OBJFPC}
{$MODESWITCH UNICODESTRINGS}

interface

function GetFileVersion(const FileName: string): string;

implementation

uses
  windows;

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

begin
end.
