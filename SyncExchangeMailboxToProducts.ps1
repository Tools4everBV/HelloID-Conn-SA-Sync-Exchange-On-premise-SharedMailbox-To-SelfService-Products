#####################################################
# HelloID-SA-Sync-Exchange-SharedMailbox-To-Products
#
# Version: 1.0.0.0
#####################################################
$VerbosePreference = 'SilentlyContinue'
$informationPreference = 'Continue'

# Make sure to create the Global variables defined below in HelloID
#HelloID Connection Configuration
$portalApiKey = $portalApiKey
$portalApiSecret = $portalApiSecret
$script:BaseUrl = $portalBaseUrl

#Target Connection Configuration     # Needed for accessing the Target System (These variables are also required for the Actions of each product)
$ExchangeAdminUsername = $ExchangeAdminUsername
$ExchangeAdminPassword = $ExchangeAdminPassword
$ExchangeConnectionUri = $ExchangeConnectionUri

#HelloID Product Configuration
$ProductAccessGroup = 'Users'           # If not found, the product is created without extra Access Group
$ProductCategory = 'NewProductCategory' # If the category is not found, it will be created
$SAProductResourceOwner = ''            # If left empty the groupname will be: "Resource owners [target-systeem] - [Product_Naam]")
$SAProductWorkflow = $null              # If empty. The Default HelloID Workflow is used. If specified Workflow does not exist the Product creation will raise an error.
$FaIcon = '500px'
$removeProduct = $true                  # If False product will be disabled
$productVisibility = 'All'

#Target System Configuration
# Dynamic property invocation
$uniqueProperty = 'GUID'              # The vaule of the property will be used as CombinedUniqueId

# [ValidateLength(4)]
$SKUPrefix = 'XCHG'                   # The prefix will be used as CombinedUniqueId. Max. 4 characters
$TargetSystemName = 'Exchange SharedMailbox'

# [validateSet('SendAs', 'FullAccess', 'SendOnBehalf')]
$PermissionTypes = 'SendAs', 'FullAccess', 'SendOnBehalf'


#region HelloID
function Get-HIDDefaultAgentPool {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003036494-GET-Get-agent-pools
    #>
    [CmdletBinding()]
    param ()

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'GET'
            Uri    = 'agentpools'
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-HIDSelfServiceProduct {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003027353-GET-Get-products
    #>
    [CmdletBinding()]
    param ()

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'GET'
            Uri    = 'selfservice/products'
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-HIDSelfServiceCategory {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003036194-GET-Get-self-service-categories
    #>
    [CmdletBinding()]
    param ()

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'GET'
            Uri    = 'selfservice/categories'
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Set-HIDSelfServiceProduct {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003038854-POST-Create-or-update-a-product
    #>
    [CmdletBinding()]
    param (
        $ProductJson
    )
    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Body   = $ProductJson
            Method = 'POST'
            uri    = 'selfservice/products'
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function New-HIDSelfServiceCategory {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003024773-POST-Create-self-service-category
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Name,

        [string]
        $SelfServiceCategoryGUID,

        [bool]
        $IsEnabled
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $category = [ordered]@{
            "name"                    = $Name
            "SelfServiceCategoryGUID" = $SelfServiceCategoryGUID
            "isEnabled"               = $IsEnabled
        } | ConvertTo-Json

        $splatParams = @{
            Method = 'POST'
            Uri    = 'selfservice/categories'
            Body   = $category
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Remove-HIDSelfServiceProduct {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003038654-DELETE-Delete-product
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $ProductGUID
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'DELETE'
            Uri    = "selfservice/products/$ProductGUID"
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Add-HIDGroupMemberActions {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003025813-POST-Create-group-member-action
    #>
    [CmdletBinding()]
    param(
        $body
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"

        $splatParams = @{
            Method = 'POST'
            Uri    = 'automationtasks/powershell'
            Body   = $body
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}




function New-HIDGroup {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003038654-DELETE-Delete-product
    #>
    [Cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $GroupName,

        [bool]
        $isEnabled
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $groupBody = @{
            name      = "$GroupName Resource Owners"
            isEnabled = $isEnabled
            userNames = ''
        } | ConvertTo-Json

        $splatParams = @{
            Method = 'POST'
            Uri    = 'groups'
            Body   = $groupBody
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $Pscmdlet.ThrowTerminatingError($_)
    }
}


function Get-HIDGroup {
    <#
    .DESCRIPTION
       https://docs.helloid.com/hc/en-us/articles/115002981813-GET-Get-specific-group
    #>
    [Cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $GroupName,

        [switch]
        $resourceGroup
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        if ($resourceGroup) {
            $groupname = "$GroupName Resource Owners"
        }
        $splatParams = @{
            Method = 'GET'
            Uri    = "groups/$groupname"
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        if ($_.ErrorDetails.Message -match 'Group not found') {
            return $null
        }
        $Pscmdlet.ThrowTerminatingError($_)
    }
}
function Add-HIDProductMember {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115002954633-POST-Link-member-to-group
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $selfServiceProductGUID,

        [Parameter(Mandatory)]
        [string]
        $MemberGUID
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'POST'
            Uri    = "selfserviceproducts/$selfServiceProductGUID/groups"
            Body   = @{
                groupGUID = $MemberGUID
            } | ConvertTo-Json
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $Pscmdlet.ThrowTerminatingError($_)
    }
}

function Add-HIDGroupMember {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115002954633-POST-Link-member-to-group
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $GroupGUID,

        [Parameter(Mandatory)]
        [string]
        $MemberGUID
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'POST'
            Uri    = "groups/$GroupGUID"
            Body   = @{
                UserGUID = $MemberGUID
            } | ConvertTo-Json
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $Pscmdlet.ThrowTerminatingError($_)
    }
}

function Add-HIDUserGroup {
    <#
    .DESCRIPTION
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $UserName,

        [Parameter()]
        [String]
        $GroupName
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatRestParameters = @{
            Method = 'POST'
            Uri    = "users/$UserName/groups"
            Body   = @{
                name = $GroupName
            } | ConvertTo-Json
        }
        Invoke-HIDRestMethod @splatRestParameters
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}


function Invoke-HIDRestmethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Method,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Uri,

        [object]
        $Body,

        [string]
        $ContentType = 'application/json'
    )

    try {
        Write-Verbose 'Switching to TLS 1.2'
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

        Write-Verbose 'Setting authorization headers'
        $apiKeySecret = "$($portalApiKey):$($portalApiSecret)"
        $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($apiKeySecret))
        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add("Authorization", "Basic $base64")
        $headers.Add("Content-Type", $ContentType)

        $splatParams = @{
            Uri     = "$($script:BaseUrl)/api/v1/$Uri"
            Headers = $headers
            Method  = $Method
        }

        if ($Body) {
            Write-Verbose 'Adding body to request'
            $splatParams['Body'] = $Body
        }

        Write-Verbose "Invoking '$Method' request to '$Uri'"
        Invoke-RestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Write-HidStatus {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]
        $Message,

        [Parameter()]
        [String]
        $Event
    )
    if ([String]::IsNullOrEmpty($portalBaseUrl)) {
        Write-Information $Message
    } else {
        Hid-Write-Status -Message $Message -Event $Event
    }
}

function Write-HidSummary {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]
        $Message,

        [Parameter()]
        [String]
        $Event
    )

    if ([String]::IsNullOrEmpty($portalBaseUrl) -eq $true) {
        Write-Output ($Message)
    } else {
        Hid-Write-Summary -Message $Message -Event $Event
    }
}

function Compare-Join {
    [OutputType([array], [array], [array])]
    param(
        [parameter()]
        [string[]]$ReferenceObject,

        [parameter()]
        [string[]]$DifferenceObject
    )
    if ($null -eq $DifferenceObject) {
        $Left = $ReferenceObject
    } elseif ($null -eq $ReferenceObject ) {
        $right = $DifferenceObject
    } else {
        $left = [string[]][Linq.Enumerable]::Except($ReferenceObject, $DifferenceObject )
        $right = [string[]][Linq.Enumerable]::Except($DifferenceObject, $ReferenceObject)
        $common = [string[]][Linq.Enumerable]::Intersect($ReferenceObject, $DifferenceObject)
    }
    Write-Output $Left , $Right, $common
}

#endregion HelloID

#region HelloId_Actions_Variables
#region SendAsRights
$AddSendAsRights = @'
#region functions
function Add-SendAsRights {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $GroupName,

        [Parameter()]
        [String]
        $groupmember
    )
    try {
        Hid-Write-Status -Message "Invoking command [$($MyInvocation.MyCommand)]" -Event Information
        $adminSecurePassword = ConvertTo-SecureString -String "$ExchangeAdminPassword" -AsPlainText -Force
        $adminCredential = [System.Management.Automation.PSCredential]::new($ExchangeAdminUsername, $adminSecurePassword)
        $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck
        $parameters = @{
            ConfigurationName = 'Microsoft.Exchange'
            ConnectionUri     = $exchangeConnectionUri
            Credential        = $adminCredential
            Authentication    = 'Kerberos'
            SessionOption     = $sessionOption
            ScriptBlock       = { Add-ADPermission -Identity $using:groupName -User $using:groupmember  -ExtendedRights "Send As" -Confirm:$false }
            ErrorAction       = "stop"
            WarningAction     = "SilentlyContinue"
        }
        Invoke-Command @parameters
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
#endregion functions

try {
    Hid-Write-Status -Message "Grant permission [$GroupMember] to mailbox [$groupname]" -Event Information
    $null = Add-SendAsRights -GroupName ($groupname.Split("-")[0].trim(" ")) -GroupMember $GroupMember

    Hid-Write-Status -Message  "Successfully granted [$GroupMember] to mailbox [$groupname]" -Event Success
    Hid-Write-Summary -Message "Successfully granted [$GroupMember] to mailbox [$groupname]" -Event Success
}
catch {
    Hid-Write-Status -Message  "Exception: $($_.Exception.Message)" -Event Error
    Hid-Write-Status -Message  "Could not grant [$GroupMember] to mailbox [$groupname]" -Event Error
    Hid-Write-Summary -Message "Could not grant [$GroupMember] to mailbox [$groupname]" -Event Failed
}
'@

$AddSendAsRightsAction = @{
    name                = 'Add-SendAsRights'
    automationContainer = 2
    objectGUID          = $null
    metaData            = '{"executeOnState":3}'
    useTemplate         = $false
    powerShellScript    = $AddSendAsRights
    variables           = @(
        @{
            "name"           = "GroupName"
            "value"          = "{{product.name}}"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "GroupMember"
            "value"          = "{{requester.contactEmail}}"
            "typeConstraint" = "string"
            "secure"         = $false
        }
    )
}
$RemoveSendAsRights = @'
#region functions
function Revoke-SendAsRights {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $GroupName,

        [Parameter()]
        [String]
        $groupmember
    )
    try {
        Hid-Write-Status -Message "Invoking command [$($MyInvocation.MyCommand)]" -Event Information
        $adminSecurePassword = ConvertTo-SecureString -String "$ExchangeAdminPassword" -AsPlainText -Force
        $adminCredential = [System.Management.Automation.PSCredential]::new($ExchangeAdminUsername, $adminSecurePassword)
        $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck
        $parameters = @{
            ConfigurationName = 'Microsoft.Exchange'
            ConnectionUri     = $exchangeConnectionUri
            Credential        = $adminCredential
            Authentication    = 'Kerberos'
            SessionOption     = $sessionOption
            ScriptBlock       = { Remove-ADPermission -Identity $using:groupName -User $using:groupmember  -ExtendedRights "Send As" -Confirm:$false }
            ErrorAction       = "stop"
            WarningAction     = "SilentlyContinue"
        }
        Invoke-Command @parameters
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
#endregion functions

try {
    Hid-Write-Status -Message "Revoke permission [$GroupMember] from mailbox [$groupname]" -Event Information
    $null = Revoke-SendAsRights -GroupName ($groupname.Split("-")[0].trim(" ")) -GroupMember $GroupMember

    Hid-Write-Status -Message  "Successfully revoked [$GroupMember] from mailbox [$groupname]" -Event Success
    Hid-Write-Summary -Message "Successfully revoked [$GroupMember] from mailbox [$groupname]" -Event Success
}
catch {
    Hid-Write-Status -Message  "Exception: $($_.Exception.Message)" -Event Error
    Hid-Write-Status -Message  "Could not revoke [$GroupMember] from mailbox [$groupname]" -Event Error
    Hid-Write-Summary -Message "Could not revoke [$GroupMember] from mailbox [$groupname]" -Event Failed
}
'@
$RemoveSendAsRightsAction = @{
    name                = 'Remove-SendAsRights'
    automationContainer = 2
    objectGUID          = $null
    metaData            = '{"executeOnState":11}'
    useTemplate         = $false
    powerShellScript    = $RemoveSendAsRights
    variables           = @(
        @{
            "name"           = "GroupName"
            "value"          = "{{product.name}}"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "GroupMember"
            "value"          = "{{requester.contactEmail}}"
            "typeConstraint" = "string"
            "secure"         = $false
        }
    )
}
#endregion SendAsRights

#region FullAccessRights
$AddFullAccessRights = @'
#region functions
function Add-FullAccessRights {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $GroupName,

        [Parameter()]
        [String]
        $groupmember
    )
    try {
        Hid-Write-Status -Message "Invoking command [$($MyInvocation.MyCommand)]" -Event Information
        $adminSecurePassword = ConvertTo-SecureString -String "$ExchangeAdminPassword" -AsPlainText -Force
        $adminCredential = [System.Management.Automation.PSCredential]::new($ExchangeAdminUsername, $adminSecurePassword)
        $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck
        $parameters = @{
            ConfigurationName = 'Microsoft.Exchange'
            ConnectionUri     = $exchangeConnectionUri
            Credential        = $adminCredential
            Authentication    = 'Kerberos'
            SessionOption     = $sessionOption
            ScriptBlock       = { Add-MailboxPermission -AccessRights FullAccess -InheritanceType All -AutoMapping:$false  -Identity $using:groupName -User $using:groupmember  -WarningAction "SilentlyContinue" }
            ErrorAction       = "stop"
        }
        Invoke-Command @parameters
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
#endregion functions

try {
    Hid-Write-Status -Message "Grant permission [$GroupMember] to mailbox [$groupname]" -Event Information
    $null = Add-FullAccessRights -GroupName ($groupname.Split("-")[0].trim(" ")) -GroupMember $GroupMember

    Hid-Write-Status -Message  "Successfully granted [$GroupMember] to mailbox [$groupname]" -Event Success
    Hid-Write-Summary -Message "Successfully granted [$GroupMember] to mailbox [$groupname]" -Event Success
}
catch {
    Hid-Write-Status -Message  "Exception: $($_.Exception.Message)" -Event Error
    Hid-Write-Status -Message  "Could not grant [$GroupMember] to mailbox [$groupname]" -Event Error
    Hid-Write-Summary -Message "Could not grant [$GroupMember] to mailbox [$groupname]" -Event Failed
}
'@

$AddFullAccessRightsAction = @{
    name                = 'Add-FullAccessRights'
    automationContainer = 2
    objectGUID          = $null
    metaData            = '{"executeOnState":3}'
    useTemplate         = $false
    powerShellScript    = $AddFullAccessRights
    variables           = @(
        @{
            "name"           = "GroupName"
            "value"          = "{{product.name}}"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "GroupMember"
            "value"          = "{{requester.contactEmail}}"
            "typeConstraint" = "string"
            "secure"         = $false
        }
    )
}

$RemoveFullAccessRights = @'
#region functions
function Revoke-FullAccessRights {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $GroupName,

        [Parameter()]
        [String]
        $groupmember
    )
    try {
        Hid-Write-Status -Message "Invoking command [$($MyInvocation.MyCommand)]" -Event Information
        $adminSecurePassword = ConvertTo-SecureString -String "$ExchangeAdminPassword" -AsPlainText -Force
        $adminCredential = [System.Management.Automation.PSCredential]::new($ExchangeAdminUsername, $adminSecurePassword)
        $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck
        $parameters = @{
            ConfigurationName = 'Microsoft.Exchange'
            ConnectionUri     = $exchangeConnectionUri
            Credential        = $adminCredential
            Authentication    = 'Kerberos'
            SessionOption     = $sessionOption
            ScriptBlock       = { Remove-MailboxPermission -AccessRights FullAccess -InheritanceType All -Identity $using:groupName -User $using:groupmember  -WarningAction "SilentlyContinue" -Confirm:$false}
            ErrorAction       = "stop"
            WarningAction     = "SilentlyContinue"
        }
        Invoke-Command @parameters
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
#endregion functions

try {
    Hid-Write-Status -Message "Revoke permission [$GroupMember] from mailbox [$groupname]" -Event Information
    $null = Revoke-FullAccessRights -GroupName ($groupname.Split("-")[0].trim(" ")) -GroupMember $GroupMember

    Hid-Write-Status -Message  "Successfully revoked [$GroupMember] from mailbox [$groupname]" -Event Success
    Hid-Write-Summary -Message "Successfully revoked [$GroupMember] from mailbox [$groupname]" -Event Success
}
catch {
    Hid-Write-Status -Message  "Exception: $($_.Exception.Message)" -Event Error
    Hid-Write-Status -Message  "Could not revoke [$GroupMember] from mailbox [$groupname]" -Event Error
    Hid-Write-Summary -Message "Could not revoke [$GroupMember] from mailbox [$groupname]" -Event Failed
}
'@

$RemoveFullAccessRightsAction = @{
    name                = 'Remove-FullAccessRights'
    automationContainer = 2
    objectGUID          = $null
    metaData            = '{"executeOnState":11}'
    useTemplate         = $false
    powerShellScript    = $RemoveFullAccessRights
    variables           = @(
        @{
            "name"           = "GroupName"
            "value"          = "{{product.name}}"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "GroupMember"
            "value"          = "{{requester.contactEmail}}"
            "typeConstraint" = "string"
            "secure"         = $false
        }
    )
}
#endregion FullAccessRights

#region
$AddSendOnBehalf = @'
#region functions
function Add-SendOnBehalf {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $GroupName,

        [Parameter()]
        [String]
        $groupmember
    )
    try {
        Hid-Write-Status -Message "Invoking command [$($MyInvocation.MyCommand)]" -Event Information
        $adminSecurePassword = ConvertTo-SecureString -String "$ExchangeAdminPassword" -AsPlainText -Force
        $adminCredential = [System.Management.Automation.PSCredential]::new($ExchangeAdminUsername, $adminSecurePassword)
        $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck
        $parameters = @{
            ConfigurationName = 'Microsoft.Exchange'
            ConnectionUri     = $exchangeConnectionUri
            Credential        = $adminCredential
            Authentication    = 'Kerberos'
            SessionOption     = $sessionOption
            ScriptBlock       = {Set-Mailbox -Identity $using:groupName -GrantSendOnBehalfTo @{Add = "$($using:GroupMember)" }  }
            ErrorAction       = "stop"
            WarningAction     = "SilentlyContinue"
        }
        Invoke-Command @parameters
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
#endregion functions

try {
    Hid-Write-Status -Message "Grant permission [$GroupMember] to mailbox [$groupname]" -Event Information
    $null = Add-SendOnBehalf -GroupName ($groupname.Split("-")[0].trim(" ")) -GroupMember $GroupMember

    Hid-Write-Status -Message  "Successfully granted [$GroupMember] to mailbox [$groupname]" -Event Success
    Hid-Write-Summary -Message "Successfully granted [$GroupMember] to mailbox [$groupname]" -Event Success
}
catch {
    Hid-Write-Status -Message  "Exception: $($_.Exception.Message)" -Event Error
    Hid-Write-Status -Message  "Could not grant [$GroupMember] to mailbox [$groupname]" -Event Error
    Hid-Write-Summary -Message "Could not grant [$GroupMember] to mailbox [$groupname]" -Event Failed
}
'@

$AddSendOnBehalfAction = @{
    name                = 'Add-SendOnBehalf'
    automationContainer = 2
    objectGUID          = $null
    metaData            = '{"executeOnState":3}'
    useTemplate         = $false
    powerShellScript    = $AddSendOnBehalf
    variables           = @(
        @{
            "name"           = "GroupName"
            "value"          = "{{product.name}}"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "GroupMember"
            "value"          = "{{requester.contactEmail}}"
            "typeConstraint" = "string"
            "secure"         = $false
        }
    )
}

$RemoveSendOnBehalf = @'
#region functions
function Revoke-SendOnBehalf {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $GroupName,

        [Parameter()]
        [String]
        $groupmember
    )
    try {
        Hid-Write-Status -Message "Invoking command [$($MyInvocation.MyCommand)]" -Event Information
        $adminSecurePassword = ConvertTo-SecureString -String "$ExchangeAdminPassword" -AsPlainText -Force
        $adminCredential = [System.Management.Automation.PSCredential]::new($ExchangeAdminUsername, $adminSecurePassword)
        $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck
        $parameters = @{
            ConfigurationName = 'Microsoft.Exchange'
            ConnectionUri     = $exchangeConnectionUri
            Credential        = $adminCredential
            Authentication    = 'Kerberos'
            SessionOption     = $sessionOption
            ScriptBlock       = {Set-Mailbox -Identity $using:groupName -GrantSendOnBehalfTo @{Remove = "$($using:GroupMember)" }  }
            ErrorAction       = "stop"
            WarningAction     = "SilentlyContinue"
        }
        Invoke-Command @parameters
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
#endregion functions
try {
    Hid-Write-Status -Message "Revoke permission [$GroupMember] from mailbox [$groupname]" -Event Information
    $null = Revoke-SendOnBehalf -GroupName ($groupname.Split("-")[0].trim(" ")) -GroupMember $GroupMember

    Hid-Write-Status -Message  "Successfully revoked [$GroupMember] from mailbox [$groupname]" -Event Success
    Hid-Write-Summary -Message "Successfully revoked [$GroupMember] from mailbox [$groupname]" -Event Success
}
catch {
    Hid-Write-Status -Message  "Exception: $($_.Exception.Message)" -Event Error
    Hid-Write-Status -Message  "Could not revoke [$GroupMember] from mailbox [$groupname]" -Event Error
    Hid-Write-Summary -Message "Could not revoke [$GroupMember] from mailbox [$groupname]" -Event Failed
}
'@
$RemoveSendOnBehalfAction = @{
    name                = 'Remove-SendOnBehalf'
    automationContainer = 2
    objectGUID          = $null
    metaData            = '{"executeOnState":11}'
    useTemplate         = $false
    powerShellScript    = $RemoveSendOnBehalf
    variables           = @(
        @{
            "name"           = "GroupName"
            "value"          = "{{product.name}}"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "GroupMember"
            "value"          = "{{requester.contactEmail}}"
            "typeConstraint" = "string"
            "secure"         = $false
        }
    )
}
#endregion

#endregion HelloId_Actions_Variables

#region TargetSystem
function Get-ExchangeSharedMailbox {
    param(
        [parameter(Mandatory)]
        $ExchangeAdminUsername,

        [parameter(Mandatory)]
        $ExchangeAdminPassword,

        [parameter(Mandatory)]
        $ExchangeConnectionUri
    )
    try {
        $adminSecurePassword = ConvertTo-SecureString -String "$ExchangeAdminPassword" -AsPlainText -Force
        $adminCredential = [System.Management.Automation.PSCredential]::new($ExchangeAdminUsername, $adminSecurePassword)
        $sessionOption = New-PSSessionOption -SkipCACheck -SkipCNCheck
        $parameters = @{
            ConfigurationName = 'Microsoft.Exchange'
            ConnectionUri     = $exchangeConnectionUri
            Credential        = $adminCredential
            Authentication    = 'Kerberos'
            SessionOption     = $sessionOption
            ScriptBlock       = { Get-Mailbox -filter '*' }
        }
        $mailBoxes = Invoke-Command @parameters
        Write-Output $mailBoxes
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}
#endregion TargetSystem

#region script
try {
    $splatExchange = @{
        ExchangeAdminUsername = $ExchangeAdminUsername
        ExchangeAdminPassword = $ExchangeAdminPassword
        ExchangeConnectionUri = $ExchangeConnectionUri
    }
    $TargetGroups = Get-ExchangeSharedMailbox @splatExchange    # Gets the groups of the Target system
    # $TargetGroups = $null              #easy way to remove all products

    Write-HidStatus -Message 'Starting synchronization of TargetSystem groups to HelloID products' -Event Information
    Write-HidStatus -Message "------[$TargetSystemName]-----------" -Event Information
    if ($TargetGroups.count -gt 0) {
        if ($null -eq $TargetGroups.$uniqueProperty) {
            throw "The specified unique property [$uniqueProperty] for the target system does exist as property in the groups"
        }
    }

    if ($TargetGroups.Count -eq 0) {
        Write-HidStatus -Message 'No Target Groups have been found' -Event Information
    } else {
        Write-HidStatus -Message "[$($TargetGroups.Count)] Target group(s)" -Event Information
    }

    $targetGroupsList = [System.Collections.Generic.List[Object]]::New()
    foreach ($group in $TargetGroups) {
        foreach ($PermissionType in $PermissionTypes) {
            $tempGroup = $group | Select-Object *
            $type = switch ( $PermissionType.tolower()) {
                'sendas' { 'SA' }
                'fullaccess' { 'FA' }
                'sendonbehalf' { 'SO' }
            }
            # SA FA SO
            $tempGroup | Add-Member @{
                CombinedUniqueId = $SKUPrefix + "$($group.$uniqueProperty)".Replace('-', '') + $type
                TypePermission   = $PermissionType
            }
            $targetGroupsList.Add($tempGroup)
        }
    }
    $TargetGroups = $targetGroupsList
    $TargetGroupsGrouped = $TargetGroups | Group-Object -Property CombinedUniqueId -AsHashTable -AsString


    Write-HidStatus -Message '------[HelloID]-----------------------' -Event Information
    Write-HidStatus -Message 'Getting default agent pool' -Event Information
    $defaultAgentPool = (Get-HIDDefaultAgentPool) | Where-Object { $_.options -eq '1' }

    Write-HidStatus -Message "Gathering the self service product category '$ProductCategory'" -Event Information
    $selfServiceCategory = (Get-HIDSelfServiceCategory) | Where-Object { $_.name -eq "$ProductCategory" }

    if ($selfServiceCategory.isEnabled -eq $false) {
        Write-HidStatus -Message "Found a disabled ProductCategory '$ProductCategory', will enable the current category" -Event Information
        $selfServiceCategory = New-HIDSelfServiceCategory -Name "$ProductCategory" -IsEnabled $true -SelfServiceCategoryGUID  $selfServiceCategory.selfServiceCategoryGUID
    } elseif ($null -eq $selfServiceCategory) {
        Write-HidStatus -Message "No ProductCategory Found will Create a new category '$ProductCategory'" -Event Information
        $selfServiceCategory = New-HIDSelfServiceCategory -Name "$ProductCategory" -IsEnabled $true
    }

    Write-HidStatus -Message 'Gathering Self service products from HelloID' -Event Information
    $selfServiceProduct = Get-HIDSelfServiceProduct
    $selfServiceProductGrouped = $selfServiceProduct | Group-Object -Property 'code' -AsHashTable -AsString

    Write-HidStatus -Message '------[Summary]-----------------------' -Event Information
    Write-HidStatus -Message "Total HelloID Self Service Product(s) found [$($selfServiceProduct.Count)]" -Event Information

    # Making sure we only manage the products of Target System
    $currentProducts = $selfServiceProduct | Where-Object { $_.code.ToLower().startswith("$($SKUPrefix.tolower())") }

    Write-HidStatus -Message "HelloID Self Service Product(s) of Target System [$TargetSystemName] found [$($currentProducts.Count)]" -Event Information

    # Null Check Reference before compare
    $currentProductsChecked = if ($null -ne $currentProducts.code) { $currentProducts.code.tolower() } else { $null }
    $targetGroupsChecked = if ($null -ne $TargetGroups.CombinedUniqueId) { $TargetGroups.CombinedUniqueId.ToLower() } else { $null }

    $productToCreateInHelloID , $productToRemoveFromHelloID, $productExistsInHelloID = Compare-Join -ReferenceObject $targetGroupsChecked -DifferenceObject $currentProductsChecked
    Write-HidStatus "[$($productToCreateInHelloID.count)] Products will be Created " -Event Information
    Write-HidStatus "[$($productExistsInHelloID.count)] Products already exist in HelloId" -Event Information
    if ($removeProduct) {
        Write-HidStatus "[$($productToRemoveFromHelloID.count)] Products will be Removed " -Event Information
    } else {
        Write-HidStatus 'Verify if there are products found which are already disabled.' -Event Information
        $productToRemoveFromHelloID = [array]($currentProducts | Where-Object { ( $_.code.ToLower() -in $productToRemoveFromHelloID) -and $_.visibility -ne 'Disabled' }).code
        Write-HidStatus "[$($productToRemoveFromHelloID.count)] Products will be disabled " -Event Information
    }

    Write-HidStatus -Message '------[Processing]------------------' -Event Information
    foreach ($productToCreate in $productToCreateInHelloID) {
        $product = $TargetGroupsGrouped[$productToCreate]
        Write-HidStatus "Creating Product [$($product.name)]" -Event Information
        $resourceOwnerGroupName = if ([string]::IsNullOrWhiteSpace($SAProductResourceOwner) ) { $product.name } else { $SAProductResourceOwner }

        $resourceOwnerGroup = Get-HIDGroup -GroupName $resourceOwnerGroupName  -ResourceGroup
        if ($null -eq $resourceOwnerGroup ) {
            Write-HidStatus "Creating a new resource owner group for Product [$($resourceOwnerGroupName ) Resource Owners]" -Event Information
            $resourceOwnerGroup = New-HIDGroup -GroupName $resourceOwnerGroupName -isEnabled $true
        }
        $productBody = @{
            Name                       = "$($product.name) - $($product.TypePermission)"
            Description                = "$TargetSystemName - $($product.name) - $($product.TypePermission)"
            ManagedByGroupGUID         = $($resourceOwnerGroup.groupGuid)
            Categories                 = @($selfServiceCategory.name)
            ApprovalWorkflowName       = $SAProductWorkflow
            AgentPoolGUID              = $defaultAgentPool.agentPoolGUID
            Icon                       = $null
            FaIcon                     = "fa-$FaIcon"
            UseFaIcon                  = $true
            IsAutoApprove              = $false
            IsAutoDeny                 = $false
            MultipleRequestOption      = 1
            IsCommentable              = $true
            HasTimeLimit               = $false
            LimitType                  = 'Fixed'
            ManagerCanOverrideDuration = $true
            ReminderTimeout            = 30
            OwnershipMaxDuration       = 90
            CreateDefaultEmailActions  = $true
            Visibility                 = $productVisibility
            Code                       = $product.CombinedUniqueId
        } | ConvertTo-Json
        $selfServiceProduct = Set-HIDSelfServiceProduct -ProductJson $productBody

        $sAAccessGroup = Get-HIDGroup -GroupName $ProductAccessGroup
        if (-not $null -eq $sAAccessGroup) {
            Write-HidStatus -Message  "Adding ProductAccessGroup [$ProductAccessGroup] to Product " -Event Information
            $null = Add-HIDProductMember -selfServiceProductGUID $selfServiceProduct.selfServiceProductGUID -MemberGUID $sAAccessGroup.groupGuid
        } else {
            Write-HidStatus -Message  "The Specified ProductAccessGroup [$ProductAccessGroup] does not exist. We will continue without adding the access Group" -Event Warning
        }

        $Actions = [System.Collections.Generic.list[object]]@()
        switch ($product.TypePermission.tolower()) {
            'sendas' {
                $Actions.Add($AddSendAsRightsAction)
                $Actions.Add($RemoveSendAsRightsAction)
                break
            }
            'fullaccess' {
                $Actions.Add($AddFullAccessRightsAction)
                $Actions.Add($RemoveFullAccessRightsAction)
            }
            'sendonbehalf' {
                $Actions.Add($AddSendOnBehalfAction)
                $Actions.Add($RemoveSendOnBehalfAction)
            }
        }

        foreach ($action in $actions) {
            Write-HidStatus -Message  "Adding action [$($action.Name)] to Product " -Event Information
            $action.objectGUID = $selfServiceProduct.selfServiceProductGUID
            $null = Add-HIDGroupMemberActions -Body ($action | ConvertTo-Json)
        }
    }

    foreach ($productToRemove in $ProductToRemoveFromHelloID) {
        $product = $selfServiceProductGrouped[$productToRemove] | Select-Object -First 1
        if ($removeProduct) {
            Write-HidStatus "Removing Product [$($product.name)]" -Event Information
            $null = Remove-HIDSelfServiceProduct -ProductGUID  $product.selfServiceProductGUID
        } else {
            Write-HidStatus "Disabling Product [$($product.name)]" -Event Information
            $product.visibility = 'Disabled'
            $disableProductBody = ConvertTo-Json ($product | Select-Object -Property * -ExcludeProperty Code)
            $null = Set-HIDSelfServiceProduct -ProductJson $disableProductBody
        }
    }

    foreach ($productToUpdate in $productExistsInHelloID) {
        # Make sure existing products are enabled
        $product = $selfServiceProductGrouped[$productToUpdate] | Select-Object -First 1
        if ($product.visibility -eq 'Disabled') {
            Write-HidStatus "Enabling existing Product [$($product.name)]" -Event Information
            $product.visibility = $productVisibility
            $product.isEnabled = $true
            $eanbleProductBody = ConvertTo-Json ($product | Select-Object -Property * -ExcludeProperty Code)
            $null = Set-HIDSelfServiceProduct -ProductJson $eanbleProductBody
        }
        Write-HidStatus "No Changes Needed. Product [$($product.name)]" -Event Information
    }

    Write-HidStatus -Message "Successfully synchronized [$TargetSystemName] to HelloID products" -Event Success
    Write-HidSummary -Message "Successfully synchronized [$TargetSystemName] to HelloID products" -Event Success
} catch {
    Write-HidStatus -Message "Error synchronization of [$TargetSystemName] to HelloID products" -Event Error
    Write-HidStatus -Message "Exception message: $($_.Exception.Message)" -Event Error
    Write-HidStatus -Message "Exception details: $($_.errordetails)" -Event Error
    Write-HidSummary -Message "Error synchronization of [$TargetSystemName] to HelloID products" -Event Failed
}
#endregion
