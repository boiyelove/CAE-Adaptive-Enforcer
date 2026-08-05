targetScope = 'resourceGroup'

@description('Explicit opt-in because this creates chargeable Azure resources.')
param deployPlatform bool = false

@description('Enable only after the Function code and risk_event entry point are deployed.')
param deployEventSubscription bool = false

@minLength(3)
@maxLength(12)
param namePrefix string = 'caeenforce'

param location string = resourceGroup().location

@description('Entra tenant accepted by the rules policy.')
param tenantId string

var suffix = uniqueString(subscription().subscriptionId, resourceGroup().id)
var storageName = take(toLower(replace('${namePrefix}${suffix}', '-', '')), 24)
var functionName = take('${namePrefix}-fn-${suffix}', 60)
var storageBlobDataOwner = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  'b7e6dc6d-f1e8-4753-8033-0f276bb0955b'
)
var storageQueueDataContributor = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '974c5e8b-45b9-4653-ba55-5f855dd0fb88'
)
var storageTableDataContributor = subscriptionResourceId(
  'Microsoft.Authorization/roleDefinitions',
  '0a9a7e1f-b9d0-4cc4-a60d-0319b160aaa3'
)

resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = if (deployPlatform) {
  name: '${namePrefix}-logs'
  location: location
  properties: {
    retentionInDays: 30
    features: {
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

resource insights 'Microsoft.Insights/components@2020-02-02' = if (deployPlatform) {
  name: '${namePrefix}-insights'
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    DisableIpMasking: false
    IngestionMode: 'LogAnalytics'
    WorkspaceResourceId: logs.id
  }
}

resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = if (deployPlatform) {
  #disable-next-line BCP334
  name: storageName
  location: location
  kind: 'StorageV2'
  sku: {
    name: 'Standard_GRS'
  }
  properties: {
    allowBlobPublicAccess: false
    allowCrossTenantReplication: false
    allowSharedKeyAccess: false
    defaultToOAuthAuthentication: true
    minimumTlsVersion: 'TLS1_2'
    publicNetworkAccess: 'Enabled'
    supportsHttpsTrafficOnly: true
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = if (deployPlatform) {
  parent: storage
  name: 'default'
  properties: {
    changeFeed: {
      enabled: true
      retentionInDays: 30
    }
    deleteRetentionPolicy: {
      enabled: true
      days: 30
    }
    isVersioningEnabled: true
  }
}

resource auditContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = if (deployPlatform) {
  parent: blobService
  name: 'audit'
  properties: {
    immutableStorageWithVersioning: {
      enabled: true
    }
    publicAccess: 'None'
  }
}

resource auditImmutability 'Microsoft.Storage/storageAccounts/blobServices/containers/immutabilityPolicies@2023-05-01' = if (deployPlatform) {
  parent: auditContainer
  name: 'default'
  properties: {
    allowProtectedAppendWrites: true
    immutabilityPeriodSinceCreationInDays: 30
  }
}

resource plan 'Microsoft.Web/serverfarms@2024-04-01' = if (deployPlatform) {
  name: '${namePrefix}-plan'
  location: location
  kind: 'elastic'
  sku: {
    name: 'EP1'
    tier: 'ElasticPremium'
  }
  properties: {
    maximumElasticWorkerCount: 3
  }
}

resource functionApp 'Microsoft.Web/sites@2024-04-01' = if (deployPlatform) {
  name: functionName
  location: location
  kind: 'functionapp,linux'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    clientAffinityEnabled: false
    httpsOnly: true
    publicNetworkAccess: 'Enabled'
    serverFarmId: plan.id
    siteConfig: {
      alwaysOn: true
      ftpsState: 'Disabled'
      http20Enabled: true
      ipSecurityRestrictions: [
        {
          action: 'Allow'
          ipAddress: 'AzureEventGrid'
          name: 'AzureEventGrid'
          priority: 100
          tag: 'ServiceTag'
        }
      ]
      ipSecurityRestrictionsDefaultAction: 'Deny'
      linuxFxVersion: 'PYTHON|3.13'
      minTlsVersion: '1.2'
      scmIpSecurityRestrictionsUseMain: true
      appSettings: [
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: insights.properties.ConnectionString
        }
        {
          name: 'AUDIT_STORAGE_ACCOUNT'
          value: storage.name
        }
        {
          name: 'AzureWebJobsStorage__accountName'
          value: storage.name
        }
        {
          name: 'AzureWebJobsStorage__credential'
          value: 'managedidentity'
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: 'python'
        }
        {
          name: 'POLICY_TENANT_ID'
          value: tenantId
        }
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE'
          value: '1'
        }
      ]
    }
  }
}

resource blobRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployPlatform) {
  name: guid(storage.id, functionApp.id, storageBlobDataOwner)
  scope: storage
  properties: {
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageBlobDataOwner
  }
}

resource queueRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployPlatform) {
  name: guid(storage.id, functionApp.id, storageQueueDataContributor)
  scope: storage
  properties: {
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageQueueDataContributor
  }
}

resource tableRole 'Microsoft.Authorization/roleAssignments@2022-04-01' = if (deployPlatform) {
  name: guid(storage.id, functionApp.id, storageTableDataContributor)
  scope: storage
  properties: {
    principalId: functionApp.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: storageTableDataContributor
  }
}

resource topic 'Microsoft.EventGrid/topics@2023-12-15-preview' = if (deployPlatform) {
  name: '${namePrefix}-signals'
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    disableLocalAuth: true
    inputSchema: 'CloudEventSchemaV1_0'
    publicNetworkAccess: 'Enabled'
  }
}

resource eventSubscription 'Microsoft.EventGrid/topics/eventSubscriptions@2023-12-15-preview' = if (deployPlatform && deployEventSubscription) {
  parent: topic
  name: 'adaptive-enforcer'
  properties: {
    destination: {
      endpointType: 'AzureFunction'
      properties: {
        resourceId: '${functionApp.id}/functions/risk_event'
        maxEventsPerBatch: 1
        preferredBatchSizeInKilobytes: 64
      }
    }
    eventDeliverySchema: 'EventGridSchema'
    filter: {
      includedEventTypes: [
        'risk.signal.v1'
      ]
    }
    retryPolicy: {
      eventTimeToLiveInMinutes: 1440
      maxDeliveryAttempts: 10
    }
  }
}

resource topicDiagnostics 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = if (deployPlatform) {
  scope: topic
  name: 'central-logs'
  properties: {
    workspaceId: logs.id
    logs: [
      {
        categoryGroup: 'allLogs'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

// Post-deployment Entra gate: admin-consent only this Graph application role
// to the Function managed identity: User.RevokeSessions.All
// appRoleId: 77f3a031-c388-4f99-b373-dc68676a979e
output functionPrincipalId string = deployPlatform ? functionApp.identity.principalId : ''
output graphApplicationRole string = 'User.RevokeSessions.All'
