# AzurePowerCommands

Microsoft Graph PowerShell commands for reviewing Microsoft Entra ID groups, directory roles, privileged identities, owners, and MFA registration.

This project is the Microsoft Graph successor to the original AzureAD/MSOnline-based `AzurePowerCommands.ps1` script.

> The examples in this README assume that the updated script is named `MgPowerCommands.ps1`.

## Features

- Recursively enumerate users, groups, and service principals in nested groups.
- Recursively resolve members assigned to Microsoft Entra directory roles.
- Identify members of selected privileged roles.
- Generate role overviews including users, groups, service principals, and owners.
- Build a consolidated list of highly privileged identities.
- Report MFA registration, capability, registered methods, preferred methods, and legacy per-user MFA state.
- Return normal PowerShell objects that can be filtered, exported, and processed further.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7.
- The [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/powershell/microsoftgraph/installation).
- A Microsoft Entra work or school account.
- Administrative consent for the required Microsoft Graph delegated permissions.
- A supported Microsoft Entra directory role when an API requires both Graph permissions and directory RBAC permissions.

The legacy AzureAD, AzureADPreview, and MSOnline modules are not required.

## Installation

Install the Microsoft Graph PowerShell SDK:

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
```

Download and import `MgPowerCommands.ps1`:

```powershell
Import-Module .\MgPowerCommands.ps1 -Force
```

The script can also be dot-sourced:

```powershell
. .\MgPowerCommands.ps1
```

Confirm that the public commands are available:

```powershell
Get-Command -Name Get-Mg* -CommandType Function | Where-Object Source -Like '*MgPowerCommands*'
```

## Connect to Microsoft Graph

The following delegated scopes cover all functionality in the script:

```powershell
$Scopes = @(
    'Directory.Read.All'
    'AuditLog.Read.All'
    'UserAuthenticationMethod.Read.All'
    'Policy.Read.All'
)

Connect-MgGraph -Scopes $Scopes
```

The scopes are used as follows:

| Scope | Used for |
|---|---|
| `Directory.Read.All` | Users, groups, service principals, owners, directory roles, and role members |
| `AuditLog.Read.All` | MFA registration information from `userRegistrationDetails` |
| `UserAuthenticationMethod.Read.All` | Detailed authentication method objects with `-Detailed` |
| `Policy.Read.All` | Legacy per-user MFA state from the Microsoft Graph beta authentication requirements endpoint |

Inspect the current Graph session with:

```powershell
Get-MgContext
```

Disconnect when finished:

```powershell
Disconnect-MgGraph
```

## Commands

### `Get-MgGroupMemberRecursive`

Recursively enumerates a Microsoft Entra group and nested groups. By default, the command returns unique user objects.

#### Return users

```powershell
Get-MgGroup -GroupId '<GROUP-ID>' |
    Get-MgGroupMemberRecursive
```

Find a group by display name:

```powershell
Get-MgGroup -All |
    Where-Object DisplayName -eq '<GROUP-NAME>' |
    Get-MgGroupMemberRecursive
```

#### Return nested groups

```powershell
Get-MgGroup -GroupId '<GROUP-ID>' |
    Get-MgGroupMemberRecursive -ReturnGroups
```

#### Return service principals

```powershell
Get-MgGroup -GroupId '<GROUP-ID>' |
    Get-MgGroupMemberRecursive -ReturnServicePrincipals
```

Returned objects include properties such as:

```text
ObjectType
ObjectId
DisplayName
UserPrincipalName
AppId
AccountEnabled
Mail
SecurityEnabled
IsAssignableToRole
```

---

### `Get-MgDirectoryRoleMemberRecursive`

Recursively enumerates the direct and nested members of an active Microsoft Entra directory role. By default, the command returns unique user objects.

#### Return users

```powershell
Get-MgDirectoryRole -DirectoryRoleId '<ROLE-ID>' |
    Get-MgDirectoryRoleMemberRecursive
```

Find a role by display name:

```powershell
Get-MgDirectoryRole -All |
    Where-Object DisplayName -eq 'Global Administrator' |
    Get-MgDirectoryRoleMemberRecursive
```

#### Return assigned groups

```powershell
Get-MgDirectoryRole -DirectoryRoleId '<ROLE-ID>' |
    Get-MgDirectoryRoleMemberRecursive -ReturnGroups
```

#### Return service principals

```powershell
Get-MgDirectoryRole -DirectoryRoleId '<ROLE-ID>' |
    Get-MgDirectoryRoleMemberRecursive -ReturnServicePrincipals
```

---

### `Get-MgPrivilegedRolesMembers`

Enumerates members of the privileged role set defined in the script.

#### Return privileged users

```powershell
Get-MgPrivilegedRolesMembers
```

```powershell
Get-MgPrivilegedRolesMembers |
    Format-Table ObjectType, DisplayName, UserPrincipalName, ObjectId -AutoSize
```

#### Return privileged role groups

```powershell
Get-MgPrivilegedRolesMembers -ReturnGroups
```

#### Return privileged service principals

```powershell
Get-MgPrivilegedRolesMembers -ReturnServicePrincipals
```

#### Export privileged users

```powershell
Get-MgPrivilegedRolesMembers |
    Export-Csv .\PrivilegedUsers.csv -NoTypeInformation -Encoding UTF8
```

---

### `Get-MgPrivilegedRolesOverview`

Generates an overview of the selected privileged Microsoft Entra roles. The output includes counts and names for users, groups, group owners, service principals, and service principal owners.

```powershell
$MgPrivilegedRolesOverview = Get-MgPrivilegedRolesOverview
$MgPrivilegedRolesOverview | Format-Table -AutoSize
```

Show all properties without table truncation:

```powershell
$MgPrivilegedRolesOverview |
    Format-List Role, UserCount, Users, GroupCount, Groups,
        GroupOwners, SPsCount, SPs, SPsOwners
```

Export the overview:

```powershell
$MgPrivilegedRolesOverview |
    Export-Csv .\PrivilegedRolesOverview.csv -NoTypeInformation -Encoding UTF8
```

The returned properties are:

```text
Role
UserCount
Users
GroupCount
Groups
GroupOwners
SPsCount
SPs
SPsOwners
```

> Store the original objects in the variable first. Do not assign the result of `Format-Table` to the variable when the data will be filtered or exported later.

---

### `Get-MgDirectoryRoleOverview`

Generates the same type of overview for all active Microsoft Entra directory roles returned by `Get-MgDirectoryRole`.

```powershell
$MgDirectoryRoleOverview = Get-MgDirectoryRoleOverview
$MgDirectoryRoleOverview | Format-Table -AutoSize
```

Show all properties:

```powershell
$MgDirectoryRoleOverview |
    Format-List Role, UserCount, Users, GroupCount, Groups,
        GroupOwners, SPsCount, SPs, SPsOwners
```

Export the overview:

```powershell
$MgDirectoryRoleOverview |
    Export-Csv .\DirectoryRoleOverview.csv -NoTypeInformation -Encoding UTF8
```

#### Difference between the overview commands

```powershell
Get-MgPrivilegedRolesOverview
```

Checks only the selected privileged roles defined in the script.

```powershell
Get-MgDirectoryRoleOverview
```

Checks every active directory role returned by Microsoft Graph.

---

### `Get-MgPrivilegedObjects`

Returns a consolidated and deduplicated collection of highly privileged users and service principals, including owners of privileged groups and service principals.

```powershell
$PrivilegedObjects = Get-MgPrivilegedObjects
$PrivilegedObjects | Format-Table -AutoSize
```

Filter the returned objects by type:

```powershell
$PrivilegedUsers = $PrivilegedObjects |
    Where-Object ObjectType -eq 'User'

$PrivilegedServicePrincipals = $PrivilegedObjects |
    Where-Object ObjectType -eq 'ServicePrincipal'
```

Export all privileged identities:

```powershell
$PrivilegedObjects |
    Export-Csv .\PrivilegedObjects.csv -NoTypeInformation -Encoding UTF8
```

---

### `Get-MgUserMFAConfiguration`

Reports MFA registration and authentication method information for users.

The primary MFA registration values come from the Microsoft Graph `userRegistrationDetails` report:

- `MFA Configured` maps to `isMfaRegistered`.
- `MFA Capable` maps to `isMfaCapable`.
- `MFA Methods` contains registered methods that can represent strong authentication.
- `Registered Methods` also includes methods that can be used only for SSPR, such as email.
- `Per-User MFA` is the legacy per-user MFA state and does not represent Conditional Access enforcement.

#### All users

```powershell
Get-MgUser -All |
    Get-MgUserMFAConfiguration
```

#### One user

```powershell
Get-MgUser -UserId 'user@contoso.com' |
    Get-MgUserMFAConfiguration
```

#### Detailed authentication methods

```powershell
Get-MgUser -UserId 'user@contoso.com' |
    Get-MgUserMFAConfiguration -Detailed |
    Format-List
```

Detailed output can include:

```text
Authentication Method Objects
MobilePhoneRegistered
OneWaySMS
TwoWayVoiceMobile
PhoneAppOTP
PhoneAppNotification
Registered Email
Registered Phone
FIDO2
WindowsHelloForBusiness
TemporaryAccessPass
```

#### MFA status of privileged users

```powershell
Get-MgPrivilegedRolesMembers |
    Get-MgUserMFAConfiguration
```

```powershell
Get-MgPrivilegedRolesMembers |
    Get-MgUserMFAConfiguration -Detailed |
    Format-List
```

#### Export MFA data

```powershell
Get-MgUser -All |
    Get-MgUserMFAConfiguration |
    Export-Csv .\MFAConfiguration.csv -NoTypeInformation -Encoding UTF8
```

> `MFA Configured` means that a user has registered for MFA. It does not prove that MFA is required for every sign-in. MFA enforcement can come from Conditional Access, Security Defaults, Identity Protection, or legacy per-user MFA.

## Migration from the previous version

| Previous command | Microsoft Graph command |
|---|---|
| `Get-AzureADGroupMemberRecursive` | `Get-MgGroupMemberRecursive` |
| `Get-AzureADDirectoryRoleMemberRecursive` | `Get-MgDirectoryRoleMemberRecursive` |
| `Get-AzureADPrivilegedRolesMembers` | `Get-MgPrivilegedRolesMembers` |
| `Get-AzureADPrivilegedRolesOverview` | `Get-MgPrivilegedRolesOverview` |
| `Get-AzureADDirectoryRoleOverview` | `Get-MgDirectoryRoleOverview` |
| `Get-AzureADPrivilegedObjects` | `Get-MgPrivilegedObjects` |
| `Get-AzureADUserMFAConfiguration` | `Get-MgUserMFAConfiguration` |

The input commands also changed:

| Previous command | Microsoft Graph equivalent |
|---|---|
| `Connect-AzureAD` | `Connect-MgGraph` |
| `Get-AzureADUser` | `Get-MgUser` |
| `Get-AzureADGroup` | `Get-MgGroup` |
| `Get-AzureADDirectoryRole` | `Get-MgDirectoryRole` |
| `Get-MsolUser` | `Get-MgUser` and the Microsoft Graph authentication reporting APIs |

Common parameter changes include:

```text
-ObjectId  -> -UserId, -GroupId, -DirectoryRoleId, or -ServicePrincipalId
-All $true -> -All
```

## Important limitations

### Active directory roles only

`Get-MgDirectoryRole` returns directory roles that are activated in the tenant. `Get-MgDirectoryRoleOverview` therefore does not list inactive role templates.

### PIM eligibility

The current commands enumerate active directory role membership. Eligible Microsoft Entra Privileged Identity Management assignments are not included.

### Static privileged role list

`Get-MgPrivilegedRolesMembers` and `Get-MgPrivilegedRolesOverview` use a role-name list defined in the script. Review this list when Microsoft adds or renames directory roles, or when a tenant treats additional roles as privileged.

### Beta endpoints

The script uses Microsoft Graph beta endpoints internally for selected compatibility and reporting operations, including the legacy per-user MFA state. Beta APIs can change and should be retested after Microsoft Graph updates.

### Group owner availability

Microsoft Graph might not return owners for some Exchange-created groups, distribution groups, or groups synchronized from an on-premises environment.

### Read permissions and directory roles

Microsoft Graph permissions alone might not be sufficient for all directory data. In delegated sessions, the signed-in user can also require an appropriate Microsoft Entra directory role. Insufficient access can result in objects containing only an ID and object type.

## Troubleshooting

### The script is not digitally signed

Files downloaded from the internet can be marked as blocked by Windows:

```powershell
Unblock-File .\MgPowerCommands.ps1
Import-Module .\MgPowerCommands.ps1 -Force
```

If an organizational policy enforces `AllSigned`, the script must be signed by a trusted code-signing certificate.

Check the effective execution policies:

```powershell
Get-ExecutionPolicy -List
```

### Results contain only IDs

Reconnect with the required scopes and confirm that admin consent has been granted:

```powershell
Disconnect-MgGraph
Connect-MgGraph -Scopes @(
    'Directory.Read.All'
    'AuditLog.Read.All'
    'UserAuthenticationMethod.Read.All'
    'Policy.Read.All'
)
```

Then inspect the session:

```powershell
Get-MgContext | Format-List
```

### Reload after updating the script

```powershell
Remove-Module MgPowerCommands -ErrorAction SilentlyContinue
Import-Module .\MgPowerCommands.ps1 -Force
```

Alternatively, open a new PowerShell session.

### Show verbose enumeration messages

```powershell
Get-MgPrivilegedRolesOverview -Verbose
```

## Microsoft Graph documentation

- [Install the Microsoft Graph PowerShell SDK](https://learn.microsoft.com/powershell/microsoftgraph/installation)
- [Connect-MgGraph](https://learn.microsoft.com/powershell/module/microsoft.graph.authentication/connect-mggraph)
- [Upgrade from Azure AD PowerShell to Microsoft Graph PowerShell](https://learn.microsoft.com/powershell/microsoftgraph/migration-steps)
- [Get-MgDirectoryRole](https://learn.microsoft.com/powershell/module/microsoft.graph.identity.directorymanagement/get-mgdirectoryrole)
- [Get-MgUserAuthenticationMethod](https://learn.microsoft.com/powershell/module/microsoft.graph.identity.signins/get-mguserauthenticationmethod)
- [Get-MgReportAuthenticationMethodUserRegistrationDetail](https://learn.microsoft.com/powershell/module/microsoft.graph.reports/get-mgreportauthenticationmethoduserregistrationdetail)
- [userRegistrationDetails resource](https://learn.microsoft.com/graph/api/resources/userregistrationdetails)

## Author

Jony Schats - [0xJs](https://github.com/0xJs)

## License

This project is licensed under the [GNU General Public License v3.0](LICENSE).
