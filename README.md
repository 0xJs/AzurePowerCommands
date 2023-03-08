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
Recursively search through privileged roles and return user objects. Use `ReturnServicePrincipals` or `ReturnGroups` to return privileged Serviceprincipals/groups.

```
Get-AzureADPrivilegedRolesMembers

ObjectId                             DisplayName UserPrincipalName  UserType
--------                             ----------- -----------------  --------
766787e8-82c1-4062-bfa9-5d4a4ca300f3 0xjs        0xjs@jonyschats.nl Member
```

```
Get-AzureADPrivilegedRolesMembers -ReturnServicePrincipals

ObjectId                             AppId                                DisplayName
--------                             -----                                -----------
5530a9cf-a45a-4662-9179-eaa8d9089605 1a93dd32-5ade-4656-9ada-6a285676eb92 Test_enterpriseapp
```

## Get-AzureADPrivilegedRolesOverview
Recursively search through privileged Azure AD roles and return a overview of the amount of members a role has and the members itself. Also checks for groups, serviceprincipals and thier owners! 

Took the roles described from [here](https://learn.microsoft.com/en-us/azure/active-directory/conditional-access/howto-conditional-access-policy-admin-mfa).

```
Get-AzureADPrivilegedRolesOverview | ft

Role                                    UserCount Users                   GroupCount Groups        GroupOwners                  SPsCount SPs                SPsOwners
----                                    --------- -----                   ---------- ------        -----------                  -------- ---                ---------
Authentication Administrator                    1 GroupUser@jonyschats.nl          1 Administrator GroupOwnerUser@jonyschats.nl        1 Test_enterpriseapp ServicePrincipalOwner@jonyschats.nl
Global Administrator                            1 0xjs@jonyschats.nl               0                                                   0
Privileged Role Administrator                   0                                  0                                                   0
Privileged authentication administrator         0                                  0                                                   0
Password administrator                          0                                  0                                                   0
User Administrator                              0                                  0                                                   0
SharePoint administrator                        0                                  0                                                   0
Security administrator                          0                                  0                                                   0
Cloud application administrator                 0                                  0                                                   0
Billing administrator                           0                                  0                                                   0
Application administrator                       0                                  0                                                   0
Helpdesk administrator                          0                                  0                                                   0
Exchange administrator                          0                                  0                                                   0
Conditional Access administrator                0                                  0                                                   0
```

## Get-AzureADDirectoryRoleOverview
Recursively search through all active Azure AD roles and return a overview of the amount of members a role has and the members itself. Also checks for groups, serviceprincipals and their owners!

```
Get-AzureADDirectoryRoleOverview

Role                         UserCount Users                                                         GroupCount Groups                   GroupOwners                  SPsCount SPs                                                     SPsOwners
----                         --------- -----                                                         ---------- ------                   -----------                  -------- ---                                                     ---------
Security Reader                      2 {NestedGroupUser@jonyschats.nl, SecurityReader@jonyschats.nl}          1 Security Reader AD Group                                     0
Global Reader                        1 SecurityReader@jonyschats.nl                                           0                                                              0
Global Administrator                 1 0xjs@jonyschats.nl                                                     0                                                              0
Authentication Administrator         1 GroupUser@jonyschats.nl                                                1 Administrator            GroupOwnerUser@jonyschats.nl        1 Test_enterpriseapp                                      ServicePrincipalOwner@jonyschats.nl
User Administrator                   0                                                                        0                                                              0
Directory Readers                    0                                                                        0                                                              2 {MicrosoftAzureActiveAuthn, Microsoft.Azure.SyncFabric}
```

## Get-AzureADPrivilegedObjects
Recursively search through privileged roles and return users and service principal identities and their owners

```
Get-AzureADPrivilegedObjects

[+] Discovered 2 users
[+] Discovered 2 group owners
[+] Discovered 1 service principals
[+] Discovered 1 service principal owners
[+] Found 4 highly privileged users
[+] Found 2 highly privileged service principals

ObjectId                             DisplayName              UserPrincipalName                   UserType
--------                             -----------              -----------------                   --------
2cc999ae-fe8e-4ce9-a18a-309d68f5bce2 GroupOwnerUser           GroupOwnerUser@jonyschats.nl        Member
59b28e90-d96b-410b-acc6-fa9ee823bfbd ServicePrincipalOwner    ServicePrincipalOwner@jonyschats.nl Member
766787e8-82c1-4062-bfa9-5d4a4ca300f3 0xjs                     0xjs@jonyschats.nl                  Member
eb815e66-31a5-45ca-bed8-2b0f5e24f62f GroupUser                GroupUser@jonyschats.nl             Member
5530a9cf-a45a-4662-9179-eaa8d9089605 Test_enterpriseapp
5fef25d5-9886-42df-9d98-de37f6ffd299 Test_enterpriseapp_owner
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
- Rewrite the cmdlets so they always return all objects, filter based on parameter. Then looping through the same commands and roles isn't neccesary to built overviews or retrieve all priviliged identities
