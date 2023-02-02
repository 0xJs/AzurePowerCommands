# AzurePowerCommands
Extra cmdlets to help with quering AzureAD related information from Azure

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

```
Get-AzureADGroup -ObjectId f5108639-9aca-4694-864e-c4e00186706b | Get-AzureADGroupMemberRecursive

ObjectId                             DisplayName     UserPrincipalName             UserType
--------                             -----------     -----------------             --------
1a9a26f4-297a-4dec-95b3-e502ec8e9dfc NestedGroupUser NestedGroupUser@jonyschats.nl Member
eb815e66-31a5-45ca-bed8-2b0f5e24f62f GroupUser       GroupUser@jonyschats.nl       Member
```

#### Get-AzureADDirectoryRoleMemberRecursive
Recursively search through roles and only return unique user objects. Requires the Get-AzureADDirectoryRole as input.

```
Get-AzureADDirectoryRole -ObjectId <ID> | Get-AzureADDirectoryRoleMemberRecursive
Get-AzureADDirectoryRole | Where-Object -Property Displayname -eq "<ROLE>" | Get-AzureADDirectoryRoleMemberRecursive
```

```
Get-AzureADDirectoryRole -ObjectId 598a6cfe-5d1a-42a7-81b6-76f4ab077152 | Get-AzureADDirectoryRoleMemberRecursive

ObjectId                             DisplayName     UserPrincipalName             UserType
--------                             -----------     -----------------             --------
1a9a26f4-297a-4dec-95b3-e502ec8e9dfc NestedGroupUser NestedGroupUser@jonyschats.nl Member
fb8a7905-e32c-4431-9e66-2968013f924f SecurityReader  SecurityReader@jonyschats.nl  Member
```

## Get-AzureADPrivilegedRolesMembers
Recursively search through privileged roles and only return unique user objects.

```
Get-AzureADPrivilegedRolesMembers

ObjectId                             DisplayName UserPrincipalName  UserType
--------                             ----------- -----------------  --------
766787e8-82c1-4062-bfa9-5d4a4ca300f3 0xjs        0xjs@jonyschats.nl Member
```

## Get-AzureADPrivilegedRolesOverview
Recursively search through privileged Azure AD roles and return a overview of the amount of members a role has and the members itself. Took the roles described from [here](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-admin-mfa).

```
Get-AzureADPrivilegedRolesOverview

Role                                    UserCount Members
----                                    --------- -------
Global Administrator                            1 0xjs@jonyschats.nl
Privileged Role Administrator                   0
Privileged authentication administrator         0
Password administrator                          0
User administrator                              0
SharePoint administrator                        0
Security administrator                          0
Helpdesk administrator                          0
Billing administrator                           0
Authentication Administrator                    0
Application administrator                       0
Exchange administrator                          0
Conditional Access administrator                0
Cloud application administrator                 0
```

## Get-AzureADDirectoryRoleOverview
Recursively search through all active Azure AD roles and return a overview of the amount of members a role has and the members itself.

```
Get-AzureADDirectoryRoleOverview

Role                 UserCount Members
----                 --------- -------
Security Reader              2 {NestedGroupUser@jonyschats.nl, SecurityReader@jonyschats.nl}
Global Reader                1 SecurityReader@jonyschats.nl
Global Administrator         1 0xjs@jonyschats.nl
```

## Get-AzureADUserMFAConfiguration
Get MFA configuration data for the user. Requires a user as input.

```
Get-AzureADUser -all $true | Get-AzureADUserMFAConfiguration

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

#### Get MFA status of all privileged users
```
Get-AzureADPrivilegedRolesMembers | Get-AzureADUserMFAConfiguration
```

# To-Do
- Update the cmdlets output examples on this github page
- Rewrite the cmdlets so they always return all objects, filter based on parameter. Then looping through the same commands and roles isn't neccesary to built overviews or retrieve all priviliged identities
