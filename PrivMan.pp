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

// This is a command-line tool for the following Windows APIs:
// LsaEnumerateAccountRights
// LsaEnumerateAccountsWithUserRight
// LsaAddAccountRights
// LsaRemoveAccountRights

program PrivMan;

{$MODE OBJFPC}
{$MODESWITCH UNICODESTRINGS}
{$R *.res}

// wargcv and wgetopts: https://github.com/Bill-Stewart/wargcv
uses
  windows,
  wargcv,
  wgetopts,
  MiscUtil,
  WindowsMessages,
  WindowsPrivileges;

const
  PROGRAM_NAME = 'PrivMan';
  PROGRAM_COPYRIGHT = 'Copyright (C) 2024 by Bill Stewart';

type
  // Groupings of command line parameters
  TParamGroup = (
    CSVReport,
    DisplayName,
    Grant,
    Help,
    List,
    ListAll,
    PrivilegeAccounts,
    Revoke,
    RevokeAll,
    Test);
  TParamSet = set of TParamGroup;
  TCommandLine = object
    ParamSet: TParamSet;
    Error: DWORD;
    Quiet: Boolean;
    ComputerName: string;
    Account: string;
    Privilege: string;
    PrivilegeDisplayName: string;
    Privileges: TStringArray;
    function GetPrivileges(const Arg: string; var Privs: TStringArray): DWORD;
    procedure Parse();
  end;

procedure Usage();
begin
  WriteLn(PROGRAM_NAME, ' ', GetFileVersion(ParamStr(0)), ' - ', PROGRAM_COPYRIGHT);
  WriteLn('This is free software and comes with ABSOLUTELY NO WARRANTY.');
  WriteLn();
  WriteLn('SYNOPSIS');
  WriteLn();
  WriteLn('Provides Windows privilege/right management functions.');
  WriteLn();
  WriteLn('USAGE');
  WriteLn();
  WriteLn(PROGRAM_NAME, ' -a <account> [-g|-r] "<privileges>" [-c computername] [-q]');
  WriteLn('Grants (-g) or revokes (-r) specified privileges/rights');
  WriteLn();
  WriteLn(PROGRAM_NAME, ' -a <account> --revokeall [-c computername] [-q]');
  WriteLn('Revokes all privileges/rights from account - USE WITH CAUTION');
  WriteLn();
  WriteLn(PROGRAM_NAME, ' -a <account> -t "<privileges>" [-c computername] [-q]');
  WriteLn('Tests if account has all specified privileges/rights');
  WriteLn('Returns 0 for NO or 1 for YES; any other exit code is an error');
  WriteLn();
  WriteLn(PROGRAM_NAME, ' -a <account> --list [-c computername] [-q]');
  WriteLn('Lists an account''s privileges/rights');
  WriteLn();
  WriteLn(PROGRAM_NAME, ' --privilegeaccounts <privilege> [-c computername] [-q]');
  WriteLn('Lists all accounts with specified privilege/right');
  WriteLn();
  WriteLn(PROGRAM_NAME, ' --displayname <privilege> [-q]');
  WriteLn('Outputs the US English display name of the specified privilege/right');
  WriteLn();
  WriteLn(PROGRAM_NAME, ' --listall');
  WriteLn('Outputs comma-delimited (CSV) list of all privileges/rights');
  WriteLn();
  WriteLn(PROGRAM_NAME, ' --csvreport [-c computername]');
  WriteLn('Outputs comma-delimited list of all accounts, privileges, and display names');
  WriteLn();
  WriteLn('COMMENTS');
  WriteLn('* <account> : User or group name, in ''authority\name'' format');
  WriteLn('* <account> can also be specified as a SID (e.g., S-1-5-32-544)');
  WriteLn('* <privileges> : List of privileges/rights, separated by spaces');
  WriteLn('* -c parameter specifies a remote computer');
  WriteLn('* -q parameter suppresses status and error messages');
  WriteLn('* Elevation (run as administrator) required for most options');
  WriteLn('* Non-zero exit code other than 1 indicates an error');
end;

function TCommandLine.GetPrivileges(const Arg: string; var Privs: TStringArray): DWORD;
var
  I: Integer;
  Priv: string;
begin
  result := ERROR_SUCCESS;
  StrSplit(Arg, ' ', Privs);
  for I := 0 to Length(Privs) - 1 do
  begin
    result := GetPrivilegeName(Trim(Privs[I]), Priv);
    if result <> 0 then
      exit;
    Privs[I] := Priv;
  end;
end;

procedure TCommandLine.Parse();
var
  Opts: array[1..14] of TOption;
  Opt: Char;
  I: Integer;
begin
  with Opts[1] do
  begin
    Name := 'account';
    Has_arg := Required_Argument;
    Flag := nil;
    Value := 'a';
  end;
  with Opts[2] do
  begin
    Name := 'computername';
    Has_arg := Required_Argument;
    Flag := nil;
    Value := 'c';
  end;
  with Opts[3] do
  begin
    Name := 'csvreport';
    Has_arg := No_Argument;
    Flag := nil;
    value := #0;
  end;
  with Opts[4] do
  begin
    Name := 'displayname';
    Has_arg := Required_Argument;
    Flag := nil;
    Value := 'd';
  end;
  with Opts[5] do
  begin
    Name := 'grant';
    Has_arg := Required_Argument;
    Flag := nil;
    Value := 'g';
  end;
  with Opts[6] do
  begin
    Name := 'help';
    Has_arg := No_Argument;
    Flag := nil;
    Value := 'h';
  end;
  with Opts[7] do
  begin
    Name := 'list';
    Has_arg := No_Argument;
    Flag := nil;
    Value := 'l';
  end;
  with Opts[8] do
  begin
    Name := 'listall';
    Has_arg := No_Argument;
    Flag := nil;
    Value := #0;
  end;
  with Opts[9] do
  begin
    Name := 'privilegeaccounts';
    Has_arg := Required_Argument;
    Flag := nil;
    Value := 'p';
  end;
  with Opts[10] do
  begin
    Name := 'quiet';
    Has_arg := No_Argument;
    Flag := nil;
    Value := 'q';
  end;
  with Opts[11] do
  begin
    Name := 'revoke';
    Has_arg := Required_Argument;
    Flag := nil;
    Value := 'r';
  end;
  with Opts[12] do
  begin
    Name := 'revokeall';
    Has_arg := No_Argument;
    Flag := nil;
    Value := #0;
  end;
  with Opts[13] do
  begin
    Name := 'test';
    Has_arg := Required_Argument;
    Flag := nil;
    Value := 't';
  end;
  with Opts[14] do
  begin
    Name := '';
    Has_arg := No_Argument;
    Flag := nil;
    Value := #0;
  end;
  ParamSet := [];
  Error := ERROR_SUCCESS;
  Account := '';
  GetComputerName(ComputerNameNetBIOS, ComputerName);
  SetLength(Privileges, 0);
  Privilege := '';
  Quiet := false;
  OptErr := false;
  repeat
    Opt := GetLongOpts('a:c:d:g:hlp:qr:t:', @Opts[1], I);
    case Opt of
      'a':  // --account
      begin
        Account := OptArg;
        if Account = '' then
          Error := ERROR_INVALID_PARAMETER;
      end;
      'c':  // --computername
      begin
        ComputerName := OptArg;
        if ComputerName = '' then
          Error := ERROR_INVALID_PARAMETER;
      end;
      'd':  // --displayname
      begin
        Error := GetPrivilegeDisplayName(OptArg, PrivilegeDisplayName);
        if Error = ERROR_SUCCESS then
          Include(ParamSet, DisplayName);
      end;
      'g':  // --grant
      begin
        Error := GetPrivileges(OptArg, Privileges);
        if Error = ERROR_SUCCESS then
          Include(ParamSet, Grant);
      end;
      'h':  // --help
      begin
        Include(ParamSet, Help);
      end;
      'l':  // --list
      begin
        Include(ParamSet, List);
      end;
      'p':  // --PrivilegeAccounts
      begin
        Error := GetPrivilegeName(OptArg, Privilege);
        if Error = ERROR_SUCCESS then
          Include(ParamSet, PrivilegeAccounts);
      end;
      'q':  // --quiet
      begin
        Quiet := true;
      end;
      'r':  // --revoke
      begin
        Error := GetPrivileges(OptArg, Privileges);
        if Error = ERROR_SUCCESS then
          Include(ParamSet, Revoke);
      end;
      't':  // --test
      begin
        Error := GetPrivileges(OptArg, Privileges);
        if ERROR = ERROR_SUCCESS then
          Include(ParamSet, Test);
      end;
      #0:
      case Opts[I].Name of
        'csvreport':
        begin
          Include(ParamSet, CSVReport);
        end;
        'listall':
        begin
          Include(ParamSet, ListAll);
        end;
        'revokeall':
        begin
          Include(ParamSet, RevokeAll);
        end;
      end;
    end;
  until Opt = EndOfOptions;
  if Error = ERROR_SUCCESS then
  begin
    // PopCnt returns number of bits set; we need a valid parameter
    if PopCnt(DWORD(ParamSet)) <> 1 then
    begin
      Error := ERROR_INVALID_PARAMETER;
    end;
    // '<=' = 'contains' for set (these params require account name)
    if (ParamSet <= [List,Grant,Revoke,RevokeAll,Test]) and (Account = '') then
    begin
      Error := ERROR_INVALID_PARAMETER;
    end;
  end;
end;

var
  RC: DWORD;
  CmdLine: TCommandLine;
  Privileges, Accounts: TStringArray;
  I, J: Integer;
  PrivilegeDisplayName: string;
  HasPrivileges: Boolean;

begin
  RC := ERROR_SUCCESS;

  CmdLine.Parse();

  if (ParamCount = 0) or (Help in CmdLine.ParamSet) then
  begin
    Usage();
    exit;
  end;

  if CmdLine.Error <> ERROR_SUCCESS then
  begin
    RC := CmdLine.Error;
    if not CmdLine.Quiet then
      WriteLn(GetWindowsMessage(RC, true));
    ExitCode := Integer(RC);
    exit;
  end;

  if ListAll in CmdLine.ParamSet then
  begin
    EnumPrivileges(Privileges);
    for I := 0 to Length(Privileges) - 1 do
    begin
      GetPrivilegeDisplayName(Privileges[I], PrivilegeDisplayName);
      WriteLn('"', Privileges[I], '","', PrivilegeDisplayName, '"');
    end;
    exit;
  end;

  if CSVReport in CmdLine.ParamSet then
  begin
    EnumPrivileges(Privileges);
    for I := 0 to Length(Privileges) - 1 do
    begin
      RC := EnumPrivilegeAccounts(CmdLine.ComputerName, Privileges[I], Accounts);
      if RC = ERROR_SUCCESS then
      begin
        GetPrivilegeDisplayName(Privileges[I], PrivilegeDisplayName);
        for J := 0 to Length(Accounts) - 1 do
          WriteLn('"', CmdLine.ComputerName, '","',
          Accounts[J], '","',
          Privileges[I], '","',
          PrivilegeDisplayName, '"');
      end;
    end;
    ExitCode := Integer(RC);
    if (RC <> ERROR_SUCCESS) and (not CmdLine.Quiet) then
      WriteLn(GetWindowsMessage(RC, true));
    exit;
  end;

  // LsaEnumerateAccountRights
  if List in CmdLine.ParamSet then
  begin
    RC := EnumAccountPrivileges(CmdLine.ComputerName, CmdLine.Account, Privileges);
    if RC = 0 then
    begin
      for I := 0 to Length(Privileges) - 1 do
        WriteLn(Privileges[I]);
    end;
    if (RC <> 0) and (not CmdLine.Quiet) then
      WriteLn(GetWindowsMessage(RC, true));
    ExitCode := Integer(RC);
    exit;
  end;

  // LsaEnumerateAccountsWithUserRight
  if PrivilegeAccounts in CmdLine.ParamSet then
  begin
    RC := EnumPrivilegeAccounts(CmdLine.ComputerName, CmdLine.Privilege, Accounts);
    if RC = ERROR_SUCCESS then
    begin
      for I := 0 to Length(Accounts) - 1 do
        WriteLn(Accounts[I]);
    end;
    if (RC <> 0) and (not CmdLine.Quiet) then
      WriteLn(GetWindowsMessage(RC, true));
    ExitCode := Integer(RC);
    exit;
  end;

  if DisplayName in CmdLine.ParamSet then
  begin
    WriteLn(CmdLine.PrivilegeDisplayName);
    exit;
  end;

  if Test in CmdLine.ParamSet then
  begin
    RC := TestAccountPrivileges(CmdLine.ComputerName, CmdLine.Account, CmdLine.Privileges, HasPrivileges);
    if RC <> ERROR_SUCCESS then
    begin
      begin
        if not CmdLine.Quiet then
          WriteLn(GetWindowsMessage(RC, true));
        ExitCode := Integer(RC);
        exit;
      end;
    end;
    if HasPrivileges then
      ExitCode := 1
    else
      ExitCode := 0;
    if not CmdLine.Quiet then
    begin
      if ExitCode = 1 then
        WriteLn('Account has all specified privileges/rights.')
      else
        WriteLn('Account does not have all specified privileges/rights.');
    end;
    exit;
  end;

  // LsaAddAccountRights
  if Grant in CmdLine.ParamSet then
  begin
    RC := AddAccountPrivileges(CmdLine.ComputerName, CmdLine.Account, CmdLine.Privileges);
    ExitCode := Integer(RC);
    if not CmdLine.Quiet then
    begin
      if RC = ERROR_SUCCESS then
        WriteLn(GetWindowsMessage(0))
      else
        WriteLn(GetWindowsMessage(RC, true));
    end;
    exit;
  end;

  // LsaRemoveAccountRights
  if Revoke in CmdLine.ParamSet then
  begin
    RC := RemoveAccountPrivileges(CmdLine.ComputerName, CmdLine.Account, CmdLine.Privileges);
    ExitCode := Integer(RC);
    if not CmdLine.Quiet then
    begin
      if RC = ERROR_SUCCESS then
        WriteLn(GetWindowsMessage(0))
      else
        WriteLn(GetWindowsMessage(RC, true));
    end;
    exit;
  end;

  if RevokeAll in CmdLine.ParamSet then
  begin
    RC := EnumAccountPrivileges(CmdLine.ComputerName, CmdLine.Account, Privileges);
    if RC = ERROR_SUCCESS then
    begin
      RC := RemoveAccountPrivileges(CmdLine.ComputerName, CmdLine.Account, Privileges);
    end;
    ExitCode := Integer(RC);
    if not CmdLine.Quiet then
    begin
      if RC = ERROR_SUCCESS then
        WriteLn(GetWindowsMessage(0))
      else
        WriteLn(GetWindowsMessage(RC, true));
    end;
    exit;
  end;

end.
