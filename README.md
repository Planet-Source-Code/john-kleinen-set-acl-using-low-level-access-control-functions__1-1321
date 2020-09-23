<div align="center">

## Set ACL using low\-level access control functions


</div>

### Description

This module provides a function that uses the Windows NT low-level access control functions to set the access rights on a folder (directory). The High-level access control functions (GetNamedSecurityInfo etc) do not function properly. They merge all ACEs for each SID. MS only acknowledges one of the four functions as malfunctioning, in fact they all are not suited for folders (directories).
 
### More Info
 
(sSrv As String, sPathname As String, szAccount As String, fNewSetRev As fNSR)

' sSrv is the machinename where to get the user SID from

' sPathname is the PATH that will get the new rights

' szAccount is the username to give new rights

' fSetNewRev specifies what to do

' f_NEW_FULL 'Will remove the existing ACL and assign Full rights

' f_REVOKE 'Will revoke the specified trustee

' f_SET_CHANGE 'Will just set new Change rights

' f_SET_FULL 'Will just set new Full rights

' f_SET_READ 'Will just set new ReadX rights

The program that i have build with this function, can be found at:

' http://home.wxs.nl/~jkleinen/setacl.zip

TRUE, ONLY when ALL calls have succeeded:

' -- The function uses:

'LookupAccountName(sSrv + vbNullChar, "System" + vbNullChar, ..

'LookupAccountName(sSrv + vbNullChar, szAccount + vbNullChar, ..

' -- Then gets the current ACL:

'GetFileSecurity(sPathname & vbNullChar, ..., SecDsc(0)...

'GetSecurityDescriptorDacl(SecDsc(0), DACLparm1, pDacl, ...

' -- then makes a new ACL:

'  InitializeAcl(NewACL(0), aclSize, aclRev)

' -- and depending on fNewSetRev copies/adds ACE's into the ACL:

'  AddAce(NewACL(0), ... for the ACE's that are needed

' -- then writes back the new ACL:

'InitializeSecurityDescriptor(SecDsc(0), SECURITY_DESCRIPTOR_...

'SetSecurityDescriptorDacl(SecDsc(0), DACLparm1, NewACL(0), ...

'SetFileSecurity(sFilename & vbNullChar, DACL_..., SecDsc(0))

' -- The return code is TRUE, ONLY when ALL calls have succeeded

(1)

' The sSrv is the server where the szAccount IS PRESENT.

' If you just created a new account and the BDCs have not yet replicated, this sSrv MUST be the PDC of the domain.

' The sPathname where the access will be applied can be on another machine that does not have to know the account yet.

' If you look at the ACL with the 'Permissions' button right after calling the function, it will display an 'Account unknown', that represents the SID.

' Wait a minute and try again, after replication the correct account name will show up.

'Side Effects:(2)

' I took special care to NEVER remove the 'System' account from the ACL.

' Note: 'System' has the same SID on all NT machines.


<span>             |<span>
---                |---
**Submitted On**   |
**By**             |[John Kleinen](https://github.com/Planet-Source-Code/PSCIndex/blob/master/ByAuthor/john-kleinen.md)
**Level**          |Advanced
**User Rating**    |5.0 (15 globes from 3 users)
**Compatibility**  |VB 5\.0, VB 6\.0
**Category**       |[Windows API Call/ Explanation](https://github.com/Planet-Source-Code/PSCIndex/blob/master/ByCategory/windows-api-call-explanation__1-39.md)
**World**          |[Visual Basic](https://github.com/Planet-Source-Code/PSCIndex/blob/master/ByWorld/visual-basic.md)
**Archive File**   |[](https://github.com/Planet-Source-Code/john-kleinen-set-acl-using-low-level-access-control-functions__1-1321/archive/master.zip)

### API Declarations

```
' Declaration part - can be inserted in the top of the module
' ACCESS things
' generic
Const Generic_read As Long = &H80000000
Const Generic_write As Long = &H40000000
Const Generic_execute As Long = &H20000000
Const Generic_all As Long = &H10000000
' standard
Const Delete = &H10000
Const Read_control = &H20000
Const Write_dac = &H40000
Const Write_owner = &H80000
Const Synchronize = &H100000
Const Standard_rights_required = &HF0000
Const Standard_rights_read = Read_control
Const Standard_rights_write = Read_control
Const Standard_rights_execute = Read_control
Const Standard_rights_all = &H1F0000
Const Specific_rights_all = &HFFFF&
Const Access_system_security = &H1000000
Const Maximum_allowed = &H2000000
' specific
Const FILE_READ_DATA = &H1& ' rows & pipe
Const FILE_LIST_DIRECTORY = &H1& ' directory
Const FILE_WRITE_DATA = &H2& ' rows & pipe
Const FILE_ADD_FILE = &H2& ' directory
Const FILE_APPEND_DATA = &H4& ' rows
Const FILE_ADD_SUBDIRECTORY = &H4& ' directory
Const FILE_CREATE_PIPE_INSTANCE = &H4& ' named pipe
Const FILE_READ_EA = &H8& ' rows & directory
Const FILE_WRITE_EA = &H10& ' rows & directory
Const FILE_EXECUTE = &H20& ' rows
Const FILE_TRAVERSE = &H20& ' directory
Const FILE_DELETE_CHILD = &H40& ' directory
Const FILE_READ_ATTRIBUTES = &H80& ' all
Const FILE_WRITE_ATTRIBUTES = &H100& ' all
' generic rights masks for files and directories
Const File_all_access As Long = Standard_rights_required Or Synchronize Or &H1FF
Const File_generic_read As Long = Standard_rights_read Or FILE_READ_DATA Or FILE_READ_ATTRIBUTES Or FILE_READ_EA Or Synchronize
Const File_generic_write As Long = Standard_rights_write Or FILE_WRITE_DATA Or FILE_WRITE_ATTRIBUTES Or FILE_WRITE_EA Or FILE_APPEND_DATA Or Synchronize
Const File_generic_execute As Long = Standard_rights_execute Or FILE_READ_ATTRIBUTES Or FILE_EXECUTE Or Synchronize
 Private Const ACCESS_MASK = &H1301BF
 ' // spiegelt folgendes wieder:
 ' // FILE_LIST_DIRECTORY
 ' // FILE_ADD_FILE
 ' // FILE_ADD_SUBDIRECTORY
 ' // FILE_READ_EA
 ' // FILE_WRITE_EA
 ' // FILE_TRAVERSE
 ' // FILE_READ_ATTRIBUTES
 ' // FILE_WRITE_ATTRIBUTES
 ' // READ_CONTROL
 ' // DELETE
 ' // SYNCHRONIZE
 Const SECURITY_DESCRIPTOR_REVISION = (1)
 Const ACL_REVISION = (2)
 Const DACL_SECURITY_INFORMATION = 4&
 Const ERROR_SUCCESS = 0&
 Const SE_FILE_OBJECT = 1&
 Const SET_ACCESS = 2& 'NOT_USED_ACCESS = 0, GRANT_ACCESS, SET_ACCESS, DENY_ACCESS,
 Const REVOKE_ACCESS = 4& 'REVOKE_ACCESS, SET_AUDIT_SUCCESS, SET_AUDIT_FAILURE
 'Const CONTAINER_INHERIT_ACE = 2&
'The predefined ace types that go into the AceType field of an Ace header.
 Const ACCESS_ALLOWED_ACE_TYPE = &H0
 Const ACCESS_DENIED_ACE_TYPE = &H1
 Const SYSTEM_AUDIT_ACE_TYPE = &H2
 Const SYSTEM_ALARM_ACE_TYPE = &H3
'The inherit flags that go into the AceFlags field of an Ace header.
 Const OBJECT_INHERIT_ACE = &H1
 Const CONTAINER_INHERIT_ACE = &H2
 Const NO_PROPAGATE_INHERIT_ACE = &H4
 Const INHERIT_ONLY_ACE = &H8
 Const VALID_INHERIT_FLAGS = &HF
 Private Type AclType
 AclRevision As Byte
 Sbz1 As Byte
 aclSize As Integer
 AceCount As Integer
 Sbz2 As Integer
 End Type
 Private Type AceType
 AceType As Byte
 AceFlags As Byte
 AceSize As Integer
 AceMask As Long
 Sid(99) As Byte
 End Type
Declare Function Sleep Lib "kernel32" (ByVal dwMilliseconds As Long) As Long
Private Declare Function FormatMessage Lib "kernel32" Alias "FormatMessageA" _
 (ByVal dwFlags As Long, ByVal lpSource As Long, ByVal dwMessageId As Long, _
 ByVal dwLanguageId As Long, ByVal lpBuffer As String, ByVal nSize As Long, _
 Arguments As Any) As Long
'eclare Function LocalAlloc Lib "kernel32" (ByVal wFlags As Long, ByVal wBytes As Long) As Long
Declare Function LocalFree Lib "kernel32" (ByVal hMem As Long) As Long
Private Declare Function LookupAccountSid Lib "advapi32.dll" Alias _
 "LookupAccountSidA" (ByVal system As String, pSid As Any, _
 ByVal Account As String, ByRef AccSize As Long, ByVal Domain As String, _
 ByRef domSize As Long, ByRef peUse As Long) As Boolean
Private Declare Function LookupAccountName Lib "advapi32.dll" Alias _
 "LookupAccountNameA" (ByVal system As String, ByVal Account As String, _
 pSid As Any, ByRef sidSize As Long, ByVal Domain As String, _
 ByRef domSize As Long, ByRef peUse As Long) As Boolean
Private Declare Function IsValidSid Lib "advapi32.dll" (pSid As Any) As Long
Private Declare Function GetLengthSid Lib "advapi32.dll" (pSid As Any) As Long
Private Declare Function GetLastError Lib "kernel32.dll" () As Long
Private Declare Function GetNamedSecurityInfo Lib "advapi32.dll" Alias "GetNamedSecurityInfoA" (ByVal ObjName As String, ByVal SE_OBJECT As Long, ByVal SecInfo As Long, ByVal pSid As Long, ByVal pSidGroup As Long, pDacl As Long, pSacl As Long, pSecurityDescriptor As Long) As Long
' pSD and pDACL always ByRef
Private Declare Function GetFileSecurity Lib "advapi32.dll" Alias "GetFileSecurityA" (ByVal szFileName As String, ByVal reqtype As Long, pSD As Any, ByVal bufsiz As Long, bufneed As Long) As Long
Private Declare Function SetFileSecurity Lib "advapi32.dll" Alias "SetFileSecurityA" (ByVal szFileName As String, ByVal reqtype As Long, pSD As Any) As Long
Private Declare Function GetSecurityDescriptorDacl Lib "advapi32.dll" (pSD As Any, ByRef pDaclPres As Long, pDacl As Any, ByRef bDaclDefaulted As Long) As Long
Private Declare Function SetSecurityDescriptorDacl Lib "advapi32.dll" (pSD As Any, ByVal pDaclPres As Long, pDacl As Any, ByVal bDaclDefaulted As Long) As Long
' Declare Function GetAclInformation Lib "advapi32.dll" (pAcl As ACL, pAclInformation As Any, ByVal nAclInformationLength As Long, ByVal dwAclInformationClass As Integer) As Long
Private Declare Function InitializeSecurityDescriptor Lib "advapi32.dll" (pSD As Any, ByVal dwRevision As Long) As Long
Private Declare Function InitializeAcl Lib "advapi32.dll" (pAcl As Any, ByVal nAclLength As Long, ByVal dwAclRevision As Long) As Long
'rivate Declare Function AddAccessAllowedAce Lib "advapi32.dll" (pAcl As Any, ByVal AceRev As Long, ByVal mask As Long, pSid As Any) As Long
'rivate Declare Function AddAccessDeniedAce Lib "advapi32.dll" (pAcl As Any, ByVal AceRev As Long, ByVal mask As Long, pSid As Any) As Long
Private Declare Function GetAce Lib "advapi32.dll" (pAcl As Any, ByVal dwAceIndex As Long, ppAce As Long) As Long
Private Declare Function AddAce Lib "advapi32.dll" (pAcl As Any, ByVal dwAceRevision As Long, ByVal dwStartingAceIndex As Long, pAceList As Any, ByVal nAceListLength As Long) As Long
Declare Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" (pDest As Any, pSource As Any, ByVal ByteLen As Long)
```


### Source Code

```
Attribute VB_Name = "ModACL"
Option Explicit
'for public function SetAccessRights
Enum fNSR
  f_NEW_FULL   'Will remove the existing ACL and assign Full rights
  f_REVOKE    'Will revoke the specified trustee
  f_SET_CHANGE  'Will just set new Change rights
  f_SET_FULL   'Will just set new Full rights
End Enum
  Const SECURITY_DESCRIPTOR_REVISION = (1)
  Const ACL_REVISION = (2)
  Const DACL_SECURITY_INFORMATION = 4&
  Const ERROR_SUCCESS = 0&
  Const SE_FILE_OBJECT = 1&
  Const SET_ACCESS = 2& 'NOT_USED_ACCESS = 0, GRANT_ACCESS, SET_ACCESS, DENY_ACCESS,
  Const REVOKE_ACCESS = 4& 'REVOKE_ACCESS, SET_AUDIT_SUCCESS, SET_AUDIT_FAILURE
  Private Type AclType
   AclRevision As Byte
   Sbz1 As Byte
   aclSize As Integer
   AceCount As Integer
   Sbz2 As Integer
  End Type
  Private Type AceType
   AceType As Byte
   AceFlags As Byte
   AceSize As Integer
   AceMask As Long
   Sid(99) As Byte
  End Type
'The predefined ace types that go into the AceType field of an Ace header.
  Const ACCESS_ALLOWED_ACE_TYPE = &H0
  Const ACCESS_DENIED_ACE_TYPE = &H1
  Const SYSTEM_AUDIT_ACE_TYPE = &H2
  Const SYSTEM_ALARM_ACE_TYPE = &H3
'The inherit flags that go into the AceFlags field of an Ace header.
  Const OBJECT_INHERIT_ACE = &H1
  Const CONTAINER_INHERIT_ACE = &H2
  Const NO_PROPAGATE_INHERIT_ACE = &H4
  Const INHERIT_ONLY_ACE = &H8
  Const VALID_INHERIT_FLAGS = &HF
Private Declare Function FormatMessage Lib "kernel32" Alias "FormatMessageA" _
  (ByVal dwFlags As Long, ByVal lpSource As Long, ByVal dwMessageId As Long, _
  ByVal dwLanguageId As Long, ByVal lpBuffer As String, ByVal nSize As Long, _
  Arguments As Any) As Long
Declare Function LocalFree Lib "kernel32" (ByVal hMem As Long) As Long
'Private Declare Function LookupAccountSid Lib "advapi32.dll" Alias _
'  "LookupAccountSidA" (ByVal system As String, pSid As Any, _
'  ByVal Account As String, ByRef AccSize As Long, ByVal Domain As String, _
'  ByRef domSize As Long, ByRef peUse As Long) As Boolean
Private Declare Function LookupAccountName Lib "advapi32.dll" Alias _
  "LookupAccountNameA" (ByVal system As String, ByVal Account As String, _
  pSid As Any, ByRef sidSize As Long, ByVal Domain As String, _
  ByRef domSize As Long, ByRef peUse As Long) As Boolean
Private Declare Function IsValidSid Lib "advapi32.dll" (pSid As Any) As Long
Private Declare Function GetLengthSid Lib "advapi32.dll" (pSid As Any) As Long
Private Declare Function GetLastError Lib "kernel32.dll" () As Long
'       pSD and pDACL always ByRef
Private Declare Function GetFileSecurity Lib "advapi32.dll" Alias "GetFileSecurityA" (ByVal szFileName As String, ByVal reqtype As Long, pSD As Any, ByVal bufsiz As Long, bufneed As Long) As Long
Private Declare Function SetFileSecurity Lib "advapi32.dll" Alias "SetFileSecurityA" (ByVal szFileName As String, ByVal reqtype As Long, pSD As Any) As Long
Private Declare Function GetSecurityDescriptorDacl Lib "advapi32.dll" (pSD As Any, ByRef pDaclPres As Long, pDacl As Any, ByRef bDaclDefaulted As Long) As Long
Private Declare Function SetSecurityDescriptorDacl Lib "advapi32.dll" (pSD As Any, ByVal pDaclPres As Long, pDacl As Any, ByVal bDaclDefaulted As Long) As Long
'    Declare Function GetAclInformation Lib "advapi32.dll" (pAcl As ACL, pAclInformation As Any, ByVal nAclInformationLength As Long, ByVal dwAclInformationClass As Integer) As Long
Private Declare Function InitializeSecurityDescriptor Lib "advapi32.dll" (pSD As Any, ByVal dwRevision As Long) As Long
Private Declare Function InitializeAcl Lib "advapi32.dll" (pAcl As Any, ByVal nAclLength As Long, ByVal dwAclRevision As Long) As Long
'rivate Declare Function AddAccessAllowedAce Lib "advapi32.dll" (pAcl As Any, ByVal AceRev As Long, ByVal mask As Long, pSid As Any) As Long
'rivate Declare Function AddAccessDeniedAce Lib "advapi32.dll" (pAcl As Any, ByVal AceRev As Long, ByVal mask As Long, pSid As Any) As Long
Private Declare Function GetAce Lib "advapi32.dll" (pAcl As Any, ByVal dwAceIndex As Long, ppAce As Long) As Long
Private Declare Function AddAce Lib "advapi32.dll" (pAcl As Any, ByVal dwAceRevision As Long, ByVal dwStartingAceIndex As Long, pAceList As Any, ByVal nAceListLength As Long) As Long
Private Declare Sub CopyMemory Lib "kernel32" Alias "RtlMoveMemory" (pDest As Any, pSource As Any, ByVal ByteLen As Long)
' *********************************************************************************************
' *********************************************************************************************
' *********************************************************************************************
Public Function SetAccessRights(sSrv As String, sFilename As String, _
                szAccount As String, fNewSetRev As fNSR) As Boolean
 Dim x as Long, i as Long, lRet As Long, long1 As Long
 Dim Sid(100) As Byte, SIS(100) As Byte
 Dim sisSize As Long, sidSize As Long, peUse As Long
 Dim sDom As String, domSize As Long
 Dim SecDsc() As Byte
 Dim pSD As Long, DACLparm1 As Long, DACLparm2 As Long
 Dim pDacl As Long
 Dim ACL As AclType
 Dim NewACL() As Byte
 Dim aclSize As Long, aclRev As Long
 Dim pAce As Long, numAce As Long
 Dim ACE As AceType
 Dim AceSize As Long, AccType As Long, AccMask As Long
  SetAccessRights = False
  On Error GoTo 0
  domSize = 25
  sDom = String(domSize, " ") ' make vb alloc memory
  sisSize = 100 ' get sid of "system"
  If LookupAccountName(sSrv + vbNullChar, "System" + vbNullChar, SIS(0), sisSize, _
              sDom, domSize, peUse) = 0 Then DisplayError "LookupAccountName - 1", GetLastError(): Exit Function
  If IsValidSid(SIS(0)) = 0 Then DisplayError "LookupAccountName - SIS", GetLastError(): Exit Function
  sidSize = 100 ' get sid of szAccount
  If LookupAccountName(sSrv + vbNullChar, szAccount + vbNullChar, Sid(0), sidSize, _
              sDom, domSize, peUse) = 0 Then DisplayError "LookupAccountName - 2", GetLastError(): Exit Function
  If IsValidSid(Sid(0)) = 0 Then DisplayError "LookupAccountName - SID", GetLastError(): Exit Function
  sidSize = GetLengthSid(Sid(0))
'1: ------------- get the D-ACL --------------------------
  SecDsc = String(2000, " ")
  If GetFileSecurity(sFilename & vbNullChar, DACL_SECURITY_INFORMATION, _
            SecDsc(0), 4000, long1) = 0 Then DisplayError "GetFileSecurity", GetLastError(): Exit Function
  DACLparm1 = 0
  If GetSecurityDescriptorDacl(SecDsc(0), DACLparm1, pDacl, DACLparm2) = 0 Then DisplayError "GetSecurityDescriptorDacl", GetLastError(): Exit Function
	' pDacl is now a pointer to the DACL in SecDsc()
  If DACLparm1 > 0 Then
    CopyMemory ACL, ByVal pDacl, 8  'Now copy to read the contents of the acl
    aclRev = ACL.AclRevision
    aclSize = ACL.aclSize
  Else
    ACL.AceCount = 0
    aclRev = ACL_REVISION
    aclSize = 0
  End If
'2: ------------- Create a new ACL --------------------------
  aclSize = aclSize + 200
  NewACL = String(aclSize/2, " ")  ' make vb alloc memory
  If InitializeAcl(NewACL(0), aclSize, aclRev) = 0 Then DisplayError "InitializeAcl", GetLastError(): Exit Function
  aclSize = 8
'3: ------------- Copy the ACEs except our ones -------------
  For i = 0 To 99
    ACE.Sid(i) = 0
  Next i
  aclRev = ACL.AclRevision
  For x = 0 To ACL.AceCount - 1
   If GetAce(ByVal pDacl, x, pAce) = 0 Then Exit Function
   CopyMemory ACE, ByVal pAce, 8
   AceSize = ACE.AceSize
   CopyMemory ACE, ByVal pAce, AceSize
   long1 = 0
   If fNewSetRev = f_NEW_FULL Then      'when new, still copy 'system'
     If CompareSid(ACE.Sid, SIS) Then long1 = 1
   Else                    'otherwise, copy all except szAccount
     If Not CompareSid(ACE.Sid, Sid) Then long1 = 1
   End If
   If long1 = 1 Then
     If AddAce(NewACL(0), aclRev, -1, ByVal pAce, AceSize) = 0 Then DisplayError "AddAce - copy", GetLastError(): Exit Function
     aclSize = aclSize + AceSize
   End If
  Next x
'4: ------------- Put in our ACEs --------------------------
  If fNewSetRev <> f_REVOKE Then
   AceSize = 8 + sidSize
   ACE.AceType = ACCESS_ALLOWED_ACE_TYPE  ' byte 0
   ACE.AceSize = AceSize          ' byte 2+3, mask = 4-7
   ACE.AceMask = IIf(fNewSetRev = f_SET_CHANGE, &H1301BF, &H1F01FF) 'Change, Full
   CopyMemory ACE.Sid(0), Sid(0), sidSize
   ACE.AceFlags = INHERIT_ONLY_ACE Or OBJECT_INHERIT_ACE
   If AddAce(NewACL(0), aclRev, 0, ACE, AceSize) = 0 Then DisplayError "AddAce - new1", GetLastError(): Exit Function
   aclSize = aclSize + AceSize
   ACE.AceFlags = CONTAINER_INHERIT_ACE  ' byte 1 - objectitself
   If AddAce(NewACL(0), aclRev, 0, ACE, AceSize) = 0 Then DisplayError "AddAce - new2", GetLastError(): Exit Function
   aclSize = aclSize + AceSize
  End If
'5: ------------- Write back the D-ACL----------------------
  CopyMemory NewACL(2), aclSize, 2
  If InitializeSecurityDescriptor(SecDsc(0), SECURITY_DESCRIPTOR_REVISION) = 0 Then _
			DisplayError "InitializeSecurityDescriptor", GetLastError(): Exit Function
  If SetSecurityDescriptorDacl(SecDsc(0), DACLparm1, NewACL(0), DACLparm2) = 0 Then _
			DisplayError "SetSecurityDescriptorDacl", GetLastError(): Exit Function
  If SetFileSecurity(sFilename & vbNullChar, DACL_SECURITY_INFORMATION, SecDsc(0)) = 0 Then _
			DisplayError "SetFileSecurity", GetLastError(): Exit Function
  SetAccessRights = True
End Function
Private Sub DisplayError(sApi As String, lCode As Long)
 Dim sMsg As String
 Dim sRtrnCode As String
 Dim lFlags As Long
 Dim lRet As Long
 Const FORMAT_MESSAGE_FROM_SYSTEM = &H1000
   sRtrnCode = Space$(256)
   lFlags = FORMAT_MESSAGE_FROM_SYSTEM
   lRet = FormatMessage(lFlags, 0&, lCode, 0&, sRtrnCode, 256&, 0&)
   If lRet = 0 Then MsgBox Err.LastDllError
   sMsg = "Error: " & sApi & vbCrLf
   sMsg = sMsg & "Code: " & lCode & vbCrLf
   sMsg = sMsg & "Desc: " & sRtrnCode
   MsgBox sMsg
End Sub
Private Function CompareSid(arr1() As Byte, Arr2() As Byte) As Boolean
Dim i As Long, len1 As Long, len2 As Long
  On Error GoTo 0
  CompareSid = False
  If IsValidSid(arr1(0)) = 0 Then Exit Function
  len1 = GetLengthSid(arr1(0))
  If IsValidSid(Arr2(0)) = 0 Then Exit Function
  len2 = GetLengthSid(Arr2(0))
  If len1 <> len2 Then Exit Function
  For i = 0 To len1 - 1
    If arr1(i) <> Arr2(i) Then Exit For
  Next i
  If i = len1 Then CompareSid = True
End Function
```

