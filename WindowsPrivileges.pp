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

unit WindowsPrivileges;

{$MODE OBJFPC}
{$MODESWITCH UNICODESTRINGS}

interface

uses
  windows;

type
  TStringArray = array of string;

// Gets proper case name of named privilege or right
function GetPrivilegeName(const Name: string; out PrivilegeName: string): DWORD;

// Gets display name of named privilege or right
function GetPrivilegeDisplayName(const Name: string; out PrivilegeDisplayName: string): DWORD;

// Enumerates list of privileges and rights
procedure EnumPrivileges(out Privileges: TStringArray);

// Adds privileges and/or rights to an account
function AddAccountPrivileges(const ComputerName, AccountName: string;
  var Privileges: TStringArray): DWORD;

// Removes privileges and/or rights from an account
function RemoveAccountPrivileges(const ComputerName, AccountName: string;
  var Privileges: TStringArray): DWORD;

// Enumerates an account's privileges and rights
function EnumAccountPrivileges(const ComputerName, AccountName: string;
  out Privileges: TStringArray): DWORD;

// Tests whether specified account has all specified privilges/rights
function TestAccountPrivileges(const ComputerName, AccountName: string;
  var Privileges: TStringArray; out HasPrivileges: Boolean): DWORD;

// Enumerates accounts with a specified privilege or right
function EnumPrivilegeAccounts(ComputerName, PrivilegeName: string;
  out Accounts: TStringArray): DWORD;

implementation

const
  POLICY_VIEW_LOCAL_INFORMATION   = $00000001;
  POLICY_VIEW_AUDIT_INFORMATION   = $00000002;
  POLICY_GET_PRIVATE_INFORMATION  = $00000004;
  POLICY_TRUST_ADMIN              = $00000008;
  POLICY_CREATE_ACCOUNT           = $00000010;
  POLICY_CREATE_SECRET            = $00000020;
  POLICY_CREATE_PRIVILEGE         = $00000040;
  POLICY_SET_DEFAULT_QUOTA_LIMITS = $00000080;
  POLICY_SET_AUDIT_REQUIREMENTS   = $00000100;
  POLICY_AUDIT_LOG_ADMIN          = $00000200;
  POLICY_SERVER_ADMIN             = $00000400;
  POLICY_LOOKUP_NAMES             = $00000800;
  POLICY_NOTIFICATION             = $00001000;
  POLICY_ALL_ACCESS = STANDARD_RIGHTS_REQUIRED or
    POLICY_VIEW_LOCAL_INFORMATION or
    POLICY_VIEW_AUDIT_INFORMATION or
    POLICY_GET_PRIVATE_INFORMATION or
    POLICY_TRUST_ADMIN or
    POLICY_CREATE_ACCOUNT or
    POLICY_CREATE_SECRET or
    POLICY_CREATE_PRIVILEGE or
    POLICY_SET_DEFAULT_QUOTA_LIMITS or
    POLICY_SET_AUDIT_REQUIREMENTS or
    POLICY_AUDIT_LOG_ADMIN or
    POLICY_SERVER_ADMIN or
    POLICY_LOOKUP_NAMES;
  STATUS_SUCCESS = ERROR_SUCCESS;
  STATUS_OBJECT_NAME_NOT_FOUND = $C0000034;
  STATUS_NO_MORE_ENTRIES = $8000001A;

type
  NTSTATUS = DWORD;

  LSA_HANDLE = Pointer;

  LSA_UNICODE_STRING = record
    Length: USHORT;
    MaximumLength: USHORT;
    Buffer: PWSTR;
  end;
  PLSA_UNICODE_STRING = ^LSA_UNICODE_STRING;
  TLSAUnicodeStringArray = array of LSA_UNICODE_STRING;

  LSA_OBJECT_ATTRIBUTES = record
    Length: ULONG;
    RootDirectory: HANDLE;
    ObjectName: PLSA_UNICODE_STRING;
    Attributes: ULONG;
    SecurityDescripter: Pointer;
    SecurityQualityOfService: Pointer;
  end;
  PLSA_OBJECT_ATTRIBUTES = ^LSA_OBJECT_ATTRIBUTES;

  LSA_ENUMERATION_INFORMATION = record
    Sid: PSID;
  end;
  PLSA_ENUMERATION_INFORMATION = ^LSA_ENUMERATION_INFORMATION;

  TPrivilege = (
    SeTrustedCredManAccessPrivilege,            // Access Credential Manager as a trusted caller
    SeNetworkLogonRight,                        // Access this computer from the network
    SeTcbPrivilege,                             // Act as part of the operating system
    SeMachineAccountPrivilege,                  // Add workstations to domain
    SeIncreaseQuotaPrivilege,                   // Adjust memory quotas for a process
    SeInteractiveLogonRight,                    // Allow log on locally
    SeRemoteInteractiveLogonRight,              // Allow log on through Remote Desktop Services
    SeBackupPrivilege,                          // Back up files and directories
    SeChangeNotifyPrivilege,                    // Bypass traverse checking
    SeSystemtimePrivilege,                      // Change the system time
    SeTimeZonePrivilege,                        // Change the time zone
    SeCreatePagefilePrivilege,                  // Create a pagefile
    SeCreateTokenPrivilege,                     // Create a token object
    SeCreateGlobalPrivilege,                    // Create global objects
    SeCreatePermanentPrivilege,                 // Create permanent shared objects
    SeCreateSymbolicLinkPrivilege,              // Create symbolic links
    SeDebugPrivilege,                           // Debug programs
    SeDenyNetworkLogonRight,                    // Deny access to this computer from the network
    SeDenyBatchLogonRight,                      // Deny log on as a batch job
    SeDenyServiceLogonRight,                    // Deny log on as a service
    SeDenyInteractiveLogonRight,                // Deny log on locally
    SeDenyRemoteInteractiveLogonRight,          // Deny log on through Remote Desktop Services
    SeEnableDelegationPrivilege,                // Enable computer and user accounts to be trusted for delegation
    SeRemoteShutdownPrivilege,                  // Force shutdown from a remote system
    SeAuditPrivilege,                           // Generate security audits
    SeImpersonatePrivilege,                     // Impersonate a client after authentication
    SeIncreaseWorkingSetPrivilege,              // Increase a process working set
    SeIncreaseBasePriorityPrivilege,            // Increase scheduling priority
    SeLoadDriverPrivilege,                      // Load and unload device drivers
    SeLockMemoryPrivilege,                      // Lock pages in memory
    SeBatchLogonRight,                          // Log on as a batch job
    SeServiceLogonRight,                        // Log on as a service
    SeSecurityPrivilege,                        // Manage auditing and security log
    SeRelabelPrivilege,                         // Modify an object label
    SeSystemEnvironmentPrivilege,               // Modify firmware environment values
    SeDelegateSessionUserImpersonatePrivilege,  // Obtain an impersonation token for another user in the same session
    SeManageVolumePrivilege,                    // Perform volume maintenance tasks
    SeProfileSingleProcessPrivilege,            // Profile single process
    SeSystemProfilePrivilege,                   // Profile system performance
    //SeUnsolicitedInputPrivilege,              // Read unsolicited input from a terminal device - N/A
    SeUndockPrivilege,                          // Remove computer from docking station
    SeAssignPrimaryTokenPrivilege,              // Replace a process level token
    SeRestorePrivilege,                         // Restore files and directories
    SeShutdownPrivilege,                        // Shut down the system
    SeSyncAgentPrivilege,                       // Synchronize directory service data
    SeTakeOwnershipPrivilege                    // Take ownership of files or other objects
  );

  TPrivilegeAction = (Add, Remove);

function ConvertSidToStringSidW(pSecurityID: PSID;
  out StringSid: LPWSTR): BOOL;
  stdcall; external 'advapi32.dll';

function ConvertStringSidToSidW(StringSid: LPCWSTR;
  out pSecurityID: PSID): BOOL;
  stdcall; external 'advapi32.dll';

function LsaNtStatusToWinError(Status: NTSTATUS): ULONG;
  stdcall; external 'advapi32.dll';

function LsaOpenPolicy(var SystemName: LSA_UNICODE_STRING;
  var ObjectAttributes: LSA_OBJECT_ATTRIBUTES;
  DesiredAccess: ACCESS_MASK;
  out PolicyHandle: LSA_HANDLE): NTSTATUS;
  stdcall; external 'advapi32.dll';

function LsaClose(ObjectHandle: LSA_HANDLE): NTSTATUS;
  stdcall; external 'advapi32.dll';

function LsaAddAccountRights(PolicyHandle: LSA_HANDLE;
  AccountSid: PSID;
  UserRights: PLSA_UNICODE_STRING;
  CountOfRights: ULONG): NTSTATUS;
  stdcall; external 'advapi32.dll';

function LsaRemoveAccountRights(PolicyHandle: LSA_HANDLE;
  AccountSid: PSID;
  AllRights: BOOLEAN;
  UserRights: PLSA_UNICODE_STRING;
  CountOfRights: ULONG): NTSTATUS;
  stdcall; external 'advapi32.dll';

function LsaEnumerateAccountRights(PolicyHandle: LSA_HANDLE;
  AccountSid: PSID;
  out UserRights: PLSA_UNICODE_STRING;
  out CountOfRights: ULONG): NTSTATUS;
  stdcall; external 'advapi32.dll';

function LsaEnumerateAccountsWithUserRight(PolicyHandle: LSA_HANDLE;
  UserRight: PLSA_UNICODE_STRING;
  out Buffer: PVOID;
  out CountReturned: ULONG): NTSTATUS;
  stdcall; external 'advapi32.dll';

function LsaFreeMemory(Buffer: PVOID): NTSTATUS;
  stdcall; external 'advapi32.dll';

function PrivilegeToString(const Privilege: TPrivilege): string;
begin
  case Privilege of
    SeTrustedCredManAccessPrivilege:           result := 'SeTrustedCredManAccessPrivilege';
    SeNetworkLogonRight:                       result := 'SeNetworkLogonRight';
    SeTcbPrivilege:                            result := 'SeTcbPrivilege';
    SeMachineAccountPrivilege:                 result := 'SeMachineAccountPrivilege';
    SeIncreaseQuotaPrivilege:                  result := 'SeIncreaseQuotaPrivilege';
    SeInteractiveLogonRight:                   result := 'SeInteractiveLogonRight';
    SeRemoteInteractiveLogonRight:             result := 'SeRemoteInteractiveLogonRight';
    SeBackupPrivilege:                         result := 'SeBackupPrivilege';
    SeChangeNotifyPrivilege:                   result := 'SeChangeNotifyPrivilege';
    SeSystemtimePrivilege:                     result := 'SeSystemtimePrivilege';
    SeTimeZonePrivilege:                       result := 'SeTimeZonePrivilege';
    SeCreatePagefilePrivilege:                 result := 'SeCreatePagefilePrivilege';
    SeCreateTokenPrivilege:                    result := 'SeCreateTokenPrivilege';
    SeCreateGlobalPrivilege:                   result := 'SeCreateGlobalPrivilege';
    SeCreatePermanentPrivilege:                result := 'SeCreatePermanentPrivilege';
    SeCreateSymbolicLinkPrivilege:             result := 'SeCreateSymbolicLinkPrivilege';
    SeDebugPrivilege:                          result := 'SeDebugPrivilege';
    SeDenyNetworkLogonRight:                   result := 'SeDenyNetworkLogonRight';
    SeDenyBatchLogonRight:                     result := 'SeDenyBatchLogonRight';
    SeDenyServiceLogonRight:                   result := 'SeDenyServiceLogonRight';
    SeDenyInteractiveLogonRight:               result := 'SeDenyInteractiveLogonRight';
    SeDenyRemoteInteractiveLogonRight:         result := 'SeDenyRemoteInteractiveLogonRight';
    SeEnableDelegationPrivilege:               result := 'SeEnableDelegationPrivilege';
    SeRemoteShutdownPrivilege:                 result := 'SeRemoteShutdownPrivilege';
    SeAuditPrivilege:                          result := 'SeAuditPrivilege';
    SeImpersonatePrivilege:                    result := 'SeImpersonatePrivilege';
    SeIncreaseWorkingSetPrivilege:             result := 'SeIncreaseWorkingSetPrivilege';
    SeIncreaseBasePriorityPrivilege:           result := 'SeIncreaseBasePriorityPrivilege';
    SeLoadDriverPrivilege:                     result := 'SeLoadDriverPrivilege';
    SeLockMemoryPrivilege:                     result := 'SeLockMemoryPrivilege';
    SeBatchLogonRight:                         result := 'SeBatchLogonRight';
    SeServiceLogonRight:                       result := 'SeServiceLogonRight';
    SeSecurityPrivilege:                       result := 'SeSecurityPrivilege';
    SeRelabelPrivilege:                        result := 'SeRelabelPrivilege';
    SeSystemEnvironmentPrivilege:              result := 'SeSystemEnvironmentPrivilege';
    SeDelegateSessionUserImpersonatePrivilege: result := 'SeDelegateSessionUserImpersonatePrivilege';
    SeManageVolumePrivilege:                   result := 'SeManageVolumePrivilege';
    SeProfileSingleProcessPrivilege:           result := 'SeProfileSingleProcessPrivilege';
    SeSystemProfilePrivilege:                  result := 'SeSystemProfilePrivilege';
    //SeUnsolicitedInputPrivilege:             result := 'SeUnsolicitedInputPrivilege';
    SeUndockPrivilege:                         result := 'SeUndockPrivilege';
    SeAssignPrimaryTokenPrivilege:             result := 'SeAssignPrimaryTokenPrivilege';
    SeRestorePrivilege:                        result := 'SeRestorePrivilege';
    SeShutdownPrivilege:                       result := 'SeShutdownPrivilege';
    SeSyncAgentPrivilege:                      result := 'SeSyncAgentPrivilege';
    SeTakeOwnershipPrivilege:                  result := 'SeTakeOwnershipPrivilege';
  else
    result := '';
  end;
end;

function LowercaseString(const S: string): string;
var
  Locale: LCID;
  Len: DWORD;
  pResult: PChar;
begin
  result := '';
  if S = '' then
    exit;
  Locale := MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT);
  Len := LCMapStringW(Locale,  // LCID    Locale
    LCMAP_LOWERCASE,           // DWORD   dwMapFlags
    PChar(S),                  // LPCWSTR lpSrcStr
    -1,                        // int     cchSrc
    nil,                       // LPWSTR  lpDestStr
    0);                        // int     cchDest
  if Len = 0 then
    exit;
  GetMem(pResult, Len * SizeOf(Char));
  if LCMapStringW(Locale,  // LCID    Locale
    LCMAP_LOWERCASE,       // DWORD   dwMapFlags
    PChar(S),              // LPCWSTR lpSrcStr
    -1,                    // int     cchSrc
    pResult,               // LPWSTR  lpDestStr
    Len) > 0 then          // int     cchDest
  begin
    result := string(pResult);
  end;
  FreeMem(pResult);
end;

function GetPrivilegeName(const Name: string; out PrivilegeName: string): DWORD;
var
  S: string;
begin
  result := 0;
  S := LowercaseString(Name);
  case S of
    'setrustedcredmanaccessprivilege':           PrivilegeName := 'SeTrustedCredManAccessPrivilege';
    'senetworklogonright':                       PrivilegeName := 'SeNetworkLogonRight';
    'setcbprivilege':                            PrivilegeName := 'SeTcbPrivilege';
    'semachineaccountprivilege':                 PrivilegeName := 'SeMachineAccountPrivilege';
    'seincreasequotaprivilege':                  PrivilegeName := 'SeIncreaseQuotaPrivilege';
    'seinteractivelogonright':                   PrivilegeName := 'SeInteractiveLogonRight';
    'seremoteinteractivelogonright':             PrivilegeName := 'SeRemoteInteractiveLogonRight';
    'sebackupprivilege':                         PrivilegeName := 'SeBackupPrivilege';
    'sechangenotifyprivilege':                   PrivilegeName := 'SeChangeNotifyPrivilege';
    'sesystemtimeprivilege':                     PrivilegeName := 'SeSystemtimePrivilege';
    'setimezoneprivilege':                       PrivilegeName := 'SeTimeZonePrivilege';
    'secreatepagefileprivilege':                 PrivilegeName := 'SeCreatePagefilePrivilege';
    'secreatetokenprivilege':                    PrivilegeName := 'SeCreateTokenPrivilege';
    'secreateglobalprivilege':                   PrivilegeName := 'SeCreateGlobalPrivilege';
    'secreatepermanentprivilege':                PrivilegeName := 'SeCreatePermanentPrivilege';
    'secreatesymboliclinkprivilege':             PrivilegeName := 'SeCreateSymbolicLinkPrivilege';
    'sedebugprivilege':                          PrivilegeName := 'SeDebugPrivilege';
    'sedenynetworklogonright':                   PrivilegeName := 'SeDenyNetworkLogonRight';
    'sedenybatchlogonright':                     PrivilegeName := 'SeDenyBatchLogonRight';
    'sedenyservicelogonright':                   PrivilegeName := 'SeDenyServiceLogonRight';
    'sedenyinteractivelogonright':               PrivilegeName := 'SeDenyInteractiveLogonRight';
    'sedenyremoteinteractivelogonright':         PrivilegeName := 'SeDenyRemoteInteractiveLogonRight';
    'seenabledelegationprivilege':               PrivilegeName := 'SeEnableDelegationPrivilege';
    'seremoteshutdownprivilege':                 PrivilegeName := 'SeRemoteShutdownPrivilege';
    'seauditprivilege':                          PrivilegeName := 'SeAuditPrivilege';
    'seimpersonateprivilege':                    PrivilegeName := 'SeImpersonatePrivilege';
    'seincreaseworkingsetprivilege':             PrivilegeName := 'SeIncreaseWorkingSetPrivilege';
    'seincreasebasepriorityprivilege':           PrivilegeName := 'SeIncreaseBasePriorityPrivilege';
    'seloaddriverprivilege':                     PrivilegeName := 'SeLoadDriverPrivilege';
    'selockmemoryprivilege':                     PrivilegeName := 'SeLockMemoryPrivilege';
    'sebatchlogonright':                         PrivilegeName := 'SeBatchLogonRight';
    'seservicelogonright':                       PrivilegeName := 'SeServiceLogonRight';
    'sesecurityprivilege':                       PrivilegeName := 'SeSecurityPrivilege';
    'serelabelprivilege':                        PrivilegeName := 'SeRelabelPrivilege';
    'sesystemenvironmentprivilege':              PrivilegeName := 'SeSystemEnvironmentPrivilege';
    'sedelegatesessionuserimpersonateprivilege': PrivilegeName := 'SeDelegateSessionUserImpersonatePrivilege';
    'semanagevolumeprivilege':                   PrivilegeName := 'SeManageVolumePrivilege';
    'seprofilesingleprocessprivilege':           PrivilegeName := 'SeProfileSingleProcessPrivilege';
    'sesystemprofileprivilege':                  PrivilegeName := 'SeSystemProfilePrivilege';
    //'seunsolicitedinputprivilege':             PrivilegeName := 'SeUnsolicitedInputPrivilege';
    'seundockprivilege':                         PrivilegeName := 'SeUndockPrivilege';
    'seassignprimarytokenprivilege':             PrivilegeName := 'SeAssignPrimaryTokenPrivilege';
    'serestoreprivilege':                        PrivilegeName := 'SeRestorePrivilege';
    'seshutdownprivilege':                       PrivilegeName := 'SeShutdownPrivilege';
    'sesyncagentprivilege':                      PrivilegeName := 'SeSyncAgentPrivilege';
    'setakeownershipprivilege':                  PrivilegeName := 'SeTakeOwnershipPrivilege';
  else
    result := ERROR_NO_SUCH_PRIVILEGE;
  end;
end;

function GetPrivilegeDisplayName(const Name: string; out PrivilegeDisplayName: string): DWORD;
var
  S: string;
begin
  result := 0;
  S := LowercaseString(Name);
  case S of
    'setrustedcredmanaccessprivilege':            PrivilegeDisplayName := 'Access Credential Manager as a trusted caller';
    'senetworklogonright':                        PrivilegeDisplayName := 'Access this computer from the network';
    'setcbprivilege':                             PrivilegeDisplayName := 'Act as part of the operating system';
    'semachineaccountprivilege':                  PrivilegeDisplayName := 'Add workstations to domain';
    'seincreasequotaprivilege':                   PrivilegeDisplayName := 'Adjust memory quotas for a process';
    'seinteractivelogonright':                    PrivilegeDisplayName := 'Allow log on locally';
    'seremoteinteractivelogonright':              PrivilegeDisplayName := 'Allow log on through Remote Desktop Services';
    'sebackupprivilege':                          PrivilegeDisplayName := 'Back up files and directories';
    'sechangenotifyprivilege':                    PrivilegeDisplayName := 'Bypass traverse checking';
    'sesystemtimeprivilege':                      PrivilegeDisplayName := 'Change the system time';
    'setimezoneprivilege':                        PrivilegeDisplayName := 'Change the time zone';
    'secreatepagefileprivilege':                  PrivilegeDisplayName := 'Create a pagefile';
    'secreatetokenprivilege':                     PrivilegeDisplayName := 'Create a token object';
    'secreateglobalprivilege':                    PrivilegeDisplayName := 'Create global objects';
    'secreatepermanentprivilege':                 PrivilegeDisplayName := 'Create permanent shared objects';
    'secreatesymboliclinkprivilege':              PrivilegeDisplayName := 'Create symbolic links';
    'sedebugprivilege':                           PrivilegeDisplayName := 'Debug programs';
    'sedenynetworklogonright':                    PrivilegeDisplayName := 'Deny access to this computer from the network';
    'sedenybatchlogonright':                      PrivilegeDisplayName := 'Deny log on as a batch job';
    'sedenyservicelogonright':                    PrivilegeDisplayName := 'Deny log on as a service';
    'sedenyinteractivelogonright':                PrivilegeDisplayName := 'Deny log on locally';
    'sedenyremoteinteractivelogonright':          PrivilegeDisplayName := 'Deny log on through Remote Desktop Services';
    'seenabledelegationprivilege':                PrivilegeDisplayName := 'Enable computer and user accounts to be trusted for delegation';
    'seremoteshutdownprivilege':                  PrivilegeDisplayName := 'Force shutdown from a remote system';
    'seauditprivilege':                           PrivilegeDisplayName := 'Generate security audits';
    'seimpersonateprivilege':                     PrivilegeDisplayName := 'Impersonate a client after authentication';
    'seincreaseworkingsetprivilege':              PrivilegeDisplayName := 'Increase a process working set';
    'seincreasebasepriorityprivilege':            PrivilegeDisplayName := 'Increase scheduling priority';
    'seloaddriverprivilege':                      PrivilegeDisplayName := 'Load and unload device drivers';
    'selockmemoryprivilege':                      PrivilegeDisplayName := 'Lock pages in memory';
    'sebatchlogonright':                          PrivilegeDisplayName := 'Log on as a batch job';
    'seservicelogonright':                        PrivilegeDisplayName := 'Log on as a service';
    'sesecurityprivilege':                        PrivilegeDisplayName := 'Manage auditing and security log';
    'serelabelprivilege':                         PrivilegeDisplayName := 'Modify an object label';
    'sesystemenvironmentprivilege':               PrivilegeDisplayName := 'Modify firmware environment values';
    'sedelegatesessionuserimpersonateprivilege':  PrivilegeDisplayName := 'Obtain an impersonation token for another user in the same session';
    'semanagevolumeprivilege':                    PrivilegeDisplayName := 'Perform volume maintenance tasks';
    'seprofilesingleprocessprivilege':            PrivilegeDisplayName := 'Profile single process';
    'sesystemprofileprivilege':                   PrivilegeDisplayName := 'Profile system performance';
    //'seunsolicitedinputprivilege':              PrivilegeDisplayName := 'Read unsolicited input from a terminal device';
    'seundockprivilege':                          PrivilegeDisplayName := 'Remove computer from docking station';
    'seassignprimarytokenprivilege':              PrivilegeDisplayName := 'Replace a process level token';
    'serestoreprivilege':                         PrivilegeDisplayName := 'Restore files and directories';
    'seshutdownprivilege':                        PrivilegeDisplayName := 'Shut down the system';
    'sesyncagentprivilege':                       PrivilegeDisplayName := 'Synchronize directory service data';
    'setakeownershipprivilege':                   PrivilegeDisplayName := 'Take ownership of files or other objects';
  else
    result := ERROR_NO_SUCH_PRIVILEGE;
  end;
end;

procedure EnumPrivileges(out Privileges: TStringArray);
var
  I: Integer;
begin
  SetLength(Privileges, Ord(High(TPrivilege)) + 1);
  for I := Ord(Low(TPrivilege)) to Ord(High(TPrivilege)) do
  begin
    Privileges[I] := PrivilegeToString(TPrivilege(I));
  end;
end;

// IMPORTANT: Caller must use LocalFree on retrieved SID structure when done
function GetAccountSid(const ComputerName, AccountName: string;
  out pSecurityID: PSID): DWORD;
var
  SidSize, AuthorityLength: DWORD;
  SidType: SID_NAME_USE;
  pAuthorityName: PChar;
begin
  result := ERROR_SUCCESS;
  SidSize := 0;
  AuthorityLength := 0;
  // Get sizes
  LookupAccountNameW(PChar(ComputerName),  // LPCWSTR       lpSystemName
    PChar(AccountName),                    // LPCWSTR       lpAccountName
    nil,                                   // PSID          Sid
    SidSize,                               // LPDWORD       cbSid
    nil,                                   // LPWSTR        ReferencedDomainName
    AuthorityLength,                       // LPDWORD       cchReferencedDomainName
    SidType);                              // PSID_NAME_USE peUse
  result := GetLastError();
  case result of
    ERROR_INSUFFICIENT_BUFFER:
    begin
      // Account name resolved; allocate buffer for SID
      result := ERROR_SUCCESS;
      pSecurityID := PSID(LocalAlloc(GMEM_FIXED,  // UINT   uFlags
        SidSize));                                // SIZE_T uBytes
      AuthorityLength := AuthorityLength * SizeOf(Char);
      GetMem(pAuthorityName, AuthorityLength);
      if not LookupAccountNameW(PChar(ComputerName),  // LPCWSTR       lpSystemName
        PChar(AccountName),                           // LPCWSTR       lpAccountName
        pSecurityID,                                  // PSID          Sid
        SidSize,                                      // LPDWORD       cbSid
        pAuthorityName,                               // LPWSTR        ReferencedDomainName
        AuthorityLength,                              // LPDWORD       cchReferencedDomainName
        SidType) then                                 // PSID_NAME_USE peUse
      begin
        result := GetLastError();
        LocalFree(HLOCAL(pSecurityID));  // HLOCAL hMem
      end;
      FreeMem(pAuthorityName);
    end;
    ERROR_NONE_MAPPED:
    begin
      // Account name didn't resolve; attempt string SID conversion
      if ConvertStringSidToSidW(PChar(AccountName),  // LPCWSTR StringSid
        pSecurityID) then                            // PSID    *Sid
      begin
        result := ERROR_SUCCESS;
      end;
    end;
  end;
end;

function GetAccountName(const ComputerName: string; const pSecurityID: PSID;
  out AccountName: string): DWORD;
var
  AccountNameLength, AuthorityNameLength: DWORD;
  pAccountName, pAuthorityName: PChar;
  SidType: SID_NAME_USE;
begin
  result := ERROR_SUCCESS;
  AccountNameLength := 0;
  AuthorityNameLength := 0;
  LookupAccountSidW(PChar(ComputerName),  // LPCWSTR       lpSystemName
    pSecurityID,                          // PSID          Sid
    nil,                                  // LPWSTR        Name
    AccountNameLength,                    // LPDWORD       cchName
    nil,                                  // LPWSTR        ReferencedDomainName
    AuthorityNameLength,                  // LPDWORD       cchReferencedDomainName
    SidType);                             // PSID_NAME_USE peUse
  result := GetLastError();
  if result <> ERROR_INSUFFICIENT_BUFFER then
    exit;
  result := ERROR_SUCCESS;
  GetMem(pAccountName, AccountNameLength * SizeOf(Char));
  GetMem(pAuthorityName, AuthorityNameLength * SizeOf(Char));
  if LookupAccountSidW(PChar(ComputerName),  // LPCWSTR       lpSystemName
       pSecurityID,                          // PSID          Sid
       pAccountName,                         // LPWSTR        Name
       AccountNameLength,                    // LPDWORD       cchName
       pAuthorityName,                       // LPWSTR        ReferencedDomainName
       AuthorityNameLength,                  // LPDWORD       cchReferencedDomainName
       SidType) then                         // PSID_NAME_USE peUse
  begin
    if string(pAuthorityName) <> '' then
      AccountName := string(pAuthorityName) + '\' + string(pAccountName)
    else
      AccountName := string(pAccountName);
  end
  else
  begin
    result := GetLastError();
  end;
  FreeMem(pAccountName);
  FreeMem(pAuthorityName);
end;

function SidToString(const pSecurityID: PSID): string;
var
  pStringSid: PChar;
begin
  result := '';
  if ConvertSidToStringSidW(pSecurityID,  // PSID   Sid
    pStringSid) then                      // LPWSTR *StringSid
  begin
    result := string(pStringSid);
    LocalFree(HLOCAL(pStringSid));  // HLOCAL hMem
  end;
end;

// Initializes a LSA_UNICODE_STRING structure from a string
function InitLsaString(const S: string; out LsaString: LSA_UNICODE_STRING): DWORD;
begin
  if Length(S) > (High(USHORT) div SizeOf(Char)) - 1 then
    result := ERROR_INSUFFICIENT_BUFFER  // string is too long
  else
    result := ERROR_SUCCESS;
  LsaString.Length := Length(S) * SizeOf(Char);
  LsaString.MaximumLength := (Length(S) + 1) * SizeOf(Char);
  LsaString.Buffer := PChar(S);
end;

function OpenLsaPolicy(const ComputerName: string; const AccessMask: ACCESS_MASK;
  out LsaPolicyHandle: LSA_HANDLE): DWORD;
var
  SystemName: LSA_UNICODE_STRING;
  ObjectAttributes: LSA_OBJECT_ATTRIBUTES;
begin
  result := InitLsaString(ComputerName, SystemName);
  if result <> ERROR_SUCCESS then
    exit;
  FillChar(ObjectAttributes, SizeOf(ObjectAttributes), 0);
  result := LsaOpenPolicy(SystemName,  // PLSA_UNICODE_STRING    SystemName
    ObjectAttributes,                  // PLSA_OBJECT_ATTRIBUTES ObjectAttributes
    AccessMask,                        // ACCESS_MASK            DesiredAccess
    LsaPolicyHandle);                  // PLSA_HANDLE            PolicyHandle
  if result <> STATUS_SUCCESS then
    result := LsaNtStatusToWinError(result);  // NTSTATUS Status
end;

function CloseLsaPolicy(const LsaPolicyHandle: LSA_HANDLE): DWORD;
begin
  result := LsaClose(LsaPolicyHandle);  // LSA_HANDLE ObjectHandle
  if result <> STATUS_SUCCESS then
    result := LsaNtStatusToWinError(result);  // NTSTATUS Status
end;

function ChangePrivileges(const Action: TPrivilegeAction;
  const ComputerName, AccountName: string; var Privileges: TStringArray): DWORD;
var
  AccessMask: ACCESS_MASK;
  LsaHandle: LSA_HANDLE;
  pSecurityID: PSID;
  I: ULONG;
  Privs: TLSAUnicodeStringArray;
  LsaString: LSA_UNICODE_STRING;
begin
  result := GetAccountSid(ComputerName, AccountName, pSecurityID);
  if result <> ERROR_SUCCESS then
    exit;

  AccessMask := POLICY_ALL_ACCESS;
  result := OpenLsaPolicy(ComputerName, AccessMask, LsaHandle);
  if result = ERROR_SUCCESS then
  begin
    SetLength(Privs, Length(Privileges));
    for I := 0 to Length(Privileges) - 1 do
    begin
      result := InitLsaString(Privileges[I], LsaString);
      if result <> ERROR_SUCCESS then
        break;
      Privs[I] := LsaString;
    end;
    if result = ERROR_SUCCESS then
    begin
      case Action of
        Add:
        begin
          result := LsaAddAccountRights(LsaHandle,  // LSA_HANDLE          PolicyHandle
            pSecurityID,                            // PSID                AccountSid
            @Privs[0],                              // PLSA_UNICODE_STRING UserRights
            Length(Privs));                         // ULONG               CountOfRights
        end;
        Remove:
        begin
          result := LsaRemoveAccountRights(LsaHandle,  // LSA_HANDLE          PolicyHandle
            pSecurityID,                               // PSID                AccountSid
            false,                                     // BOOLEAN             AllRights
            @Privs[0],                                 // PLSA_UNICODE_STRING UserRights
            Length(Privs));                            // ULONG               CountOfRights
        end;
      end;
      if result <> STATUS_SUCCESS then
        result := LsaNtStatusToWinError(result);  // NTSTATUS Status
    end;
    CloseLsaPolicy(LsaHandle);
  end;

  LocalFree(HLOCAL(pSecurityID));  // HLOCAL hMem
end;

function AddAccountPrivileges(const ComputerName, AccountName: string;
  var Privileges: TStringArray): DWORD;
begin
  if Length(Privileges) = 0 then
    result := ERROR_SUCCESS
  else
    result := ChangePrivileges(Add, ComputerName, AccountName, Privileges);
end;

function RemoveAccountPrivileges(const ComputerName, AccountName: string;
  var Privileges: TStringArray): DWORD;
begin
  if Length(Privileges) = 0 then
    result := ERROR_SUCCESS
  else
    result := ChangePrivileges(Remove, ComputerName, AccountName, Privileges);
end;

function EnumAccountPrivileges(const ComputerName, AccountName: string;
  out Privileges: TStringArray): DWORD;
var
  pSecurityID: PSID;
  AccessMask: ACCESS_MASK;
  LsaHandle: LSA_HANDLE;
  pPrivileges, pPrivilege: PLSA_UNICODE_STRING;
  Count, I: ULONG;
begin
  result := GetAccountSid(ComputerName, AccountName, pSecurityID);
  if result <> ERROR_SUCCESS then
    exit;

  AccessMask := POLICY_LOOKUP_NAMES;
  result := OpenLsaPolicy(ComputerName, AccessMask, LsaHandle);
  if result = ERROR_SUCCESS then
  begin
    result := LsaEnumerateAccountRights(LsaHandle,  // LSA_HANDLE          PolicyHandle
      pSecurityID,                                  // PSID                AccountSid
      pPrivileges,                                  // PLSA_UNICODE_STRING *UserRights
      Count);                                       // PULONG              CountOfRights
    case result of
      STATUS_OBJECT_NAME_NOT_FOUND:
      begin
        // No assignments = not an error
        result := STATUS_SUCCESS;
        SetLength(Privileges, 0);
      end;
      STATUS_SUCCESS:
      begin
        SetLength(Privileges, Count);
        pPrivilege := pPrivileges;
        for I := 0 to Count - 1 do
        begin
          // Why SetLength and Move? MSDN doc page for LSA_UNICODE_STRING says
          // "Note that the strings returned by the various LSA functions might
          // not be null-terminated." Based on this comment, we'll use the
          // Length member and copy the string rather than cast.
          SetLength(Privileges[I], pPrivilege^.Length div SizeOf(Char));
          Move(pPrivilege^.Buffer^, Privileges[I][1], pPrivilege^.Length);
          Inc(pPrivilege);
        end;
      end;
    end;
    if result <> STATUS_SUCCESS then
      result := LsaNtStatusToWinError(result);  // NTSTATUS Status
    LsaFreeMemory(pPrivileges);  // PVOID Buffer
    CloseLsaPolicy(LsaHandle);
  end;

  LocalFree(HLOCAL(pSecurityID));  // HLOCAL hMem
end;

function TestAccountPrivileges(const ComputerName, AccountName: string;
  var Privileges: TStringArray; out HasPrivileges: Boolean): DWORD;
var
  AccountPrivs: TStringArray;
  NumMatches, I, J: Integer;
  Privilege: string;
begin
  result := EnumAccountPrivileges(ComputerName, AccountName, AccountPrivs);
  if result <> ERROR_SUCCESS then
    exit;
  if Length(AccountPrivs) = 0 then
  begin
    HasPrivileges := false;
    exit;
  end;
  NumMatches := 0;
  for I := 0 to Length(Privileges) - 1 do
  begin
    result := GetPrivilegeName(Privileges[I], Privilege);
    if result = 0 then
    begin
      for J := 0 to Length(AccountPrivs) - 1 do
      begin
        if Privilege = AccountPrivs[J] then
        begin
          Inc(NumMatches);
          break;
        end;
      end;
    end
    else
      break;
  end;
  if result = 0 then
    HasPrivileges := NumMatches = Length(Privileges);
end;

function EnumPrivilegeAccounts(ComputerName, PrivilegeName: string;
  out Accounts: TStringArray): DWORD;
var
  AccessMask: ACCESS_MASK;
  LsaHandle: LSA_HANDLE;
  LsaString: LSA_UNICODE_STRING;
  pBuf: PVOID;
  Count, I: ULONG;
  pBufEntry: PLSA_ENUMERATION_INFORMATION;
  AccountName: string;
begin
  AccessMask := POLICY_LOOKUP_NAMES or POLICY_VIEW_LOCAL_INFORMATION;
  result := OpenLsaPolicy(ComputerName, AccessMask, LsaHandle);
  if result <> ERROR_SUCCESS then
    exit;

  result := InitLsaString(PrivilegeName, LsaString);
  if result = ERROR_SUCCESS then
  begin
    result := LsaEnumerateAccountsWithUserRight(LsaHandle,  // LSA_HANDLE          PolicyHandle
      @LsaString,                                           // PLSA_UNICODE_STRING UserRight,
      pBuf,                                                 // PVOID               *Buffer
      Count);                                               // PULONG              CountReturned
    case result of
      STATUS_NO_MORE_ENTRIES:
      begin
        // No accounts assigned = not an error
        result := STATUS_SUCCESS;
        SetLength(Accounts, 0);
      end;
      STATUS_SUCCESS:
      begin
        SetLength(Accounts, Count);
        pBufEntry := pBuf;
        for I := 0 to Count - 1 do
        begin
          if GetAccountName(ComputerName, pBufEntry^.Sid, AccountName) <> 0 then
            AccountName := SidToString(pBufEntry^.Sid);
          Accounts[I] := AccountName;
          Inc(pBufEntry);
        end;
        LsaFreeMemory(pBuf);  // PVOID Buffer
      end;
    end;
    if result <> STATUS_SUCCESS then
      result := LsaNtStatusToWinError(result);  // NTSTATUS Status
  end;

  CloseLsaPolicy(LsaHandle);
end;

initialization

finalization

end.
