<?php

return [
    /*
    |--------------------------------------------------------------------------
    | Tenant ID
    |--------------------------------------------------------------------------
    |
    | This value is equal to the 'Directory (tenant) ID' as found in the Azure
    | portal
    |
    */
    'tenant_id' => env('AZURE_TENANT_ID', ''),

    /*
    |--------------------------------------------------------------------------
    | Client Info
    |--------------------------------------------------------------------------
    |
    | These values are equal to 'Application (client) ID' and the secret you
    | made in 'Client secrets' as found in the Azure portal
    |
    */
    'client' => [
        'id' => env('AZURE_CLIENT_ID', ''),
        'secret' => env('AZURE_CLIENT_SECRET', ''),
    ],

    /*
    |--------------------------------------------------------------------------
    | Resource ID
    |--------------------------------------------------------------------------
    |
    | This value is equal to the 'Object ID' as found in the Azure portal
    |
    */
    'resource' => env('AZURE_RESOURCE', ''),

    /*
    |--------------------------------------------------------------------------
    | Domain Hint
    |--------------------------------------------------------------------------
    |
    | This value can be used to help users know which email address they
    | should login with.
    | https://azure.microsoft.com/en-us/updates/app-service-auth-and-azure-ad-domain-hints/
    |
    */
    'domain_hint' => env('AZURE_DOMAIN_HINT', ''),

    /*
    |--------------------------------------------------------------------------
    | Permission Scope
    |--------------------------------------------------------------------------
    |
    | This value indicates the permissions granted to the OAUTH session.
    | https://docs.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0
    |
    */
    'scope' => env('AZURE_SCOPE', 'User.Read'),
];