// Deployment values for CAE-Adaptive-Enforcer (main.bicep).
// Values are synthetic and safe by default; review placeholders before what-if or deployment.
using './main.bicep'

// Controls whether this optional deployment path is enabled.
param deployPlatform = false

// Controls whether this optional deployment path is enabled.
param deployEventSubscription = false

// Defines deterministic naming for this example environment.
param namePrefix = 'caeenforce'

// Selects the Azure region explicitly for this environment.
param location = 'westeurope'

// Supplies a synthetic identity or scope identifier; replace it with the approved value.
param tenantId = '00000000-0000-4000-8000-000000000001'
