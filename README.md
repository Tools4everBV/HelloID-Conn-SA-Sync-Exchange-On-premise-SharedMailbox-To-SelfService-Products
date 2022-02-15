HelloID-Conn-SA-Sync-Exchange-On-premise-SharedMailbox-To-SelfService-Products

| :warning: Warning |
|:---------------------------|
| Note that this HelloID connector has not been tested in a production environment! |

<!-- TABLE OF CONTENTS -->
## Table of Contents
- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [Getting started](#Getting-started)
  - [Prerequisites](#Prerequisites)
  - [Connection settings](#Connection-settings)
  - [Remarks](#Remarks)
- [Getting help](#getting-help)
- [HelloID Docs](#helloid-docs)


## Introduction
By using this connector, you will have the ability to create HelloId SelfService Products based on Exchange Shared Mailboxes. It manages only the products of the target system. The existing and manually created products are unmanaged and excluded from the sync.

The created Self-service Products are intended to manage the permissions of the Exchange Shared Mailboxes. For each mailbox, there will be one or more self-service products created. Depending on the number of permission types you specify.
The name of the products will be Mailbox name + the type of permission. Example : "Accounting Department - FullAccess" or "Accounting Department - SendOnBehalf"


## Getting started

### Prerequisites
- [ ] Make sure you have Windows PowerShell 5.1 installed on the server where the HelloID agent and Service Automation agent are running.
  > The connector is compatible with older versions of Windows PowerShell. Although we cannot guarantuee the compatibility.
- [ ] Define the Global variables for your Exchange Environment


### Connection settings

The connection settings are defined in the automation variables [user defined variables](https://docs.helloid.com/hc/en-us/articles/360014169933-How-to-Create-and-Manage-User-Defined-Variables). And the Product configuration can be configured in the script


| Variable name                 | Description                                                  | Notes                                               |
| ----------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| $portalBaseUrl                | HelloID Base Url                        | (Default Global Variable)    |
| $portalApiKey                 | HelloID Api Key                         | (Default Global Variable)    |
| $portalApiSecret              | HelloID Api Secret                      | (Default Global Variable)    |
| $ExchangeAdminUsername        | Exchange BaseUrl/Powershell             | **Define as Global Varaible**  |
| $ExchangeAdminPassword        | Exchange Api Key                        | **Define as Global Varaible**  |
| $ExchangeConnectionUri        | Exchange Api Secret                     | **Define as Global Varaible**|
| $ProductAccessGroup           | HelloID Product Access Group            | *If not found, the product is created without an Access Group* |
| $ProductCategory              | HelloID Product Category                | *If the category is not found, it will be created* |
| $SAProductResourceOwner       | HelloID Product Resource Owner Group    | *If left empty the groupname will be: "Resource owners [target-systeem] - [Product_Naam]")* |
| $SAProductWorkflow            | HelloID Product Approval workflow       | *If empty. The Default HelloID Workflow is used. If specified Workflow does not exist the Product creation will raise an error.* |
| $FaIcon                       | HelloID Product fa-icon name              | |
| $removeProduct                | HelloID Remove Product instead of Disable| |
| $productVisibility            | HelloID Product Visibility                | "ALL" |
| $uniqueProperty               | Target Groups Unique Key                  | The vaule will be used as CombinedUniqueId|
| $SKUPrefix                    | HelloID SKU prefix (Max. 4 characters)    | The prefix will be used as CombinedUniqueId |
| $TargetSystemName             | HelloID Prefix of product description     | |
| $PermissionTypes              | PermissionTypes for the products ( 'SendAs', 'FullAccess' or 'SendOnBehalf' )  | |


## Remarks
- The Products are only created and disable/deleted. No Update take place.
> When a Product already exists, the prodcut will be skipped (No update takes place).
- When the RemoveProduct switch is adjusted to remove the products. The products will be delete from HelloID instead of Disable. This will remove also the previous disabled products (by the sync).
- The managers of the sharedmailboxes are not added in the "Resource Owner Group" of the products
- The Unique identifier (CombineduniqueId / SKU)   is builded as follows:
  $SKUPrefix + GUID of the sharedmailboxes without dashes + Abbreviation of the permission Type

## Getting help
> _For more information on how to configure a HelloID PowerShell scheduled task, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/115003253294-Create-Custom-Scheduled-Tasks) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
