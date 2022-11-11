# AzurePowerCommands
Extra cmdlets to help with quering security related information from Azure

# Usage
```
. .\AzurePowerCommands.ps1
Import-Module .\AzureAD.psd1
Import-Module .\MSOnline.psd1
Connect-AzureAD
Connect-MsolService
```

# Cmdlets and examples
#### Get-AzureADGroupMemberRecursive
Recursively search through groups and only return unique user objects. Requires the Get-AzureADGroup as input.

```
Get-AzureADGroup -ObjectId <ID> | Get-AzureADGroupMemberRecursive
Get-AzureADGroup | Where-Object -Property Displayname -eq "<GROUP>" | Get-AzureADGroupMemberRecursive
```

#### Get-AzureADDirectoryRoleMemberRecursive
Recursively search through roles and only return unique user objects. Requires the Get-AzureADDirectoryRole as input.

```
Get-AzureADDirectoryRole -ObjectId <ID> | Get-AzureADDirectoryRoleMemberRecursive
Get-AzureADDirectoryRole | Where-Object -Property Displayname -eq "<ROLE>" | Get-AzureADDirectoryRoleMemberRecursive
```

## Get-AzureADPrivilegedRolesMembers
Recursively search through privileged roles and only return unique user objects. Uses the roles "Security administrator", "Exchange Administrator", "Global administrator", "Conditional Access administrator", "SharePoint administrator", "Helpdesk administrator", "Billing administrator", "User administrator", "Authentication administrator"

```
Get-AzureADPrivilegedRolesMembers

ObjectId                             DisplayName UserPrincipalName  UserType
--------                             ----------- -----------------  --------
766787e8-82c1-4062-bfa9-5d4a4ca300f3 0xjs        0xjs@jonyschats.nl Member
```

## Get-AzureADPrivilegedRolesOverview
Recursively search through privileged Azure AD roles and return a overview of the amount of members a role has and the members itself.

```
Get-AzureADPrivilegedRolesOverview

Role                             UserCount Members
----                             --------- -------
Global Administrator                     1 0xjs@jonyschats.nl
Billing administrator                    0
Helpdesk administrator                   0
User administrator                       0
Authentication administrator             0
Exchange Administrator                   0
Security administrator                   0
SharePoint administrator                 0
Conditional Access administrator         0
```

## Get-AzureADDirectoryRoleOverview
Recursively search through all active Azure AD roles and return a overview of the amount of members a role has and the members itself.

```
Get-AzureADDirectoryRoleOverview

Role                 UserCount Members
----                 --------- -------
Global Reader                1 SecurityReader@jonyschats.nl
Security Reader              1 SecurityReader@jonyschats.nl
Global Administrator         1 0xjs@jonyschats.nl
```

## Get-AzureADUserMFAConfiguration
Get MFA configuration data for the user. Requires a user as input.

```
Get-AzureADUser | Get-AzureADUserMFAConfiguration

UserPrincipalName             MFA Configured MFA Default
-----------------             -------------- -----------
NestedGroupUser@jonyschats.nl           True Authenticator
0xjs@jonyschats.nl                      True Microsoft Authenticator
GroupUser@jonyschats.nl                 True Microsoft Authenticator
SecurityReader@jonyschats.nl            True Authenticator
```


```
Get-MsolUser -ObjectId 766787e8-82c1-4062-bfa9-5d4a4ca300f3 | Get-AzureADUserMFAConfiguration -Detailed

UserPrincipalName    : 0xjs@jonyschats.nl
MFA Configured       : True
MFA Default          : Microsoft Authenticator
Per-User MFA         : Enforced
OneWaySMS            : True
TwoWayVoiceMobile    : True
PhoneAppOTP          : True
PhoneAppNotification : True
Registered Email     : fakeemail@jonyschats.nl
Registered Phone     : +31 06123456789
```
