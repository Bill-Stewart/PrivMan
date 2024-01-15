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

unit StringUtil;

{$MODE OBJFPC}
{$MODESWITCH UNICODESTRINGS}

interface

type
  TStringArray = array of string;

function Trim(S: string): string;

procedure StrSplit(S, Delim: string; var Dest: TStringArray);

implementation

uses
  windows;


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

begin
end.
