# Laravel Azure Middleware

Provides Azure Authentication Middleware for a Laravel App.  If you like this, checkout <a href="https://github.com/rootinc/laravel-saml2-middleware">Laravel Saml Middleware</a>

## Normal Installation

1. From the command line, run `composer require rootinc/laravel-azure-middleware`
2. After Composer has installed the package, run `php artisan vendor:publish --provider="RootInc\LaravelAzureMiddleware\AzureServiceProvider"` to install the config file to `config/azure.php`
3. Add the login and login callback routes to you router (by default `routes/web.php`) like shown below:
```php
Route::get('/azure/login', [\RootInc\LaravelAzureMiddleware\Azure::class, 'azure'])->name('azure.login');
Route::get('/azure/callback', [\RootInc\LaravelAzureMiddleware\Azure::class, 'azurecallback']);
```

4. Open `App/Http/Kernel.php` and add `'azure' => \RootInc\LaravelAzureMiddleware\Azure::class,` to the `$routeMiddleware` array to register the middleware.
5. Open `.env` and add the following variables (with your own values):
```
AZURE_TENANT_ID=your-azuread-tenant-id
AZURE_CLIENT_ID=your-app-registration-application-id
AZURE_CLIENT_SECRET=your-app-registration-client-secret
AZURE_RESOURCE=https://graph.microsoft.com
```
All these values can be gotten from your tenant through https://portal.azure.com.
6. As of version 0.8.0, the variable `AZURE_SCOPE` was added to the project, which are permissions to be used for the request.  You can read more about these here: https://docs.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0
7. Additionally, an optional variable, `AZURE_DOMAIN_HINT` was added, so it can be used to help users know which email address they should login with.  More info here: https://azure.microsoft.com/en-us/updates/app-service-auth-and-azure-ad-domain-hints/
8. In your App Registration on https://portal.azure.com/, set the `Redirect URIs` (often referred to as reply URLs) to the `/azure/callback` route with the full url (example: https://yourwebsite.com/azure/callback or http://localhost:8000 when running development locally).
9. Add the `azure` middleware to your route groups on any routes that needs to be protected by authentication and enjoy :tada:
10. If you need custom callbacks, see [Extended Installation](#extended-installation).

__NOTE: As of version 0.8.0, the project uses v2 of Azure's login API, which allows it to pass scopes, or permissions that can used.__

## Routing

As shown in [Normal Installation](#normal-installation), step 3.
The route path and name can be whatever you need it to be.

For example, instead of 
```php
Route::get('/azure/login', [\RootInc\LaravelAzureMiddleware\Azure::class,'azure'])->name('azure.login');
```
you could use
```php
Route::get('/login', [\RootInc\LaravelAzureMiddleware\Azure::class,'azure'])->name('login');
```

### Front End Login Button

Please refer to [Microsoft's branding guidelines](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-add-branding-in-azure-ad-apps) for login buttons.

## Extended Installation

The [Normal Installation](#normal-installation) implements the login process for users.
However, if you need to store this user in a database, as well as login the user with Laravel auth, you need some extra configuration. There are two callbacks that are recommended to extend from the Azure class called `success` and `fail`.

This guide will show you how to extent the Root Laravel Azure Middleware Library for you application:

1. Follow the [Normal Installation](#normal-installation) guide
2. Make a new middleware with Artisan command `php artisan make:middleware AzureAuthentication`. This creates the file `AzureAuthentication.php` in the `App\Http\Middleware` folder of your project.
3. Open the newly created file (from step 2) and remove all text and paste in the following:

```php
<?php

namespace App\Http\Middleware;

use RootInc\LaravelAzureMiddleware\Azure as Azure;
use Microsoft\Graph\Graph;
use Microsoft\Graph\Model;

use Auth;

use App\User;

class AzureAuthentication extends Azure
{
    protected function success($request, $access_token, $refresh_token, $profile)
    {
        $graph = new Graph();
        $graph->setAccessToken($access_token);
        
        $graph_user = $graph->createRequest("GET", "/me")
                      ->setReturnType(Model\User::class)
                      ->execute();
        
        $userPrincipalName = strtolower($graph_user->getUserPrincipalName());

        $user = User::updateOrCreate(['email' => $userPrincipalName], [
            'name' => $graph_user->getDisplayName(),
        ]);

        Auth::login($user, true);

        return parent::success($request, $access_token, $refresh_token, $profile);
    }
}
```

The above gives us a way to add/update users after a successful handshake. `$profile` contains all sorts of metadata that can be used to create or update our user.  More information here: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-oauth-code#jwt-token-claims . The default implementation redirects to the intended url, or `/`; So in this example, the parent is called.

3. The `web.php` routes need to be updated to the following:

```php
Route::get('/azure/login', [\App\Http\Middleware\AzureAuthentication::class, 'azure'])->name('azure.login');
Route::get('/azure/callback', [\App\Http\Middleware\AzureAuthentication::class, 'azurecallback']);
Route::get('/azure/logout', [\App\Http\Middleware\AzureAuthentication::class, 'azurelogout'])->name('azure.logout');
```

4. Finally, open `App/Http/Kernel.php` and change the middleware implementation of the `azure` key to be `'azure' => \App\Http\Middleware\AzureAuthentication::class,`

## Other Extending Options

#### Callback on Every Handshake

As of version 0.4.0, there was added a callback after every successful request (handshake) from Azure. The default is to call the `$next` closure. However, if you want to update the user, you can use the following example:

```php
<?php

namespace App\Http\Middleware;

use Closure;

use RootInc\LaravelAzureMiddleware\Azure as Azure;

use Auth;
use Carbon\Carbon;

use App\User;

class AzureAuthentication extends Azure
{
    protected function handlecallback($request, Closure $next, $access_token, $refresh_token)
    {
        $user = Auth::user();
        if($user === null) // If the application looses user data while user is authenticated with Laravel "catch" (i.e: User is deleted)
            return response()->redirectToRoute('azure.login'); // Make sure the route name is correct if you changed it

        $user->updated_at = Carbon::now();

        $user->save();

        return parent::handlecallback($request, $next, $access_token, $refresh_token);
    }
}
```

Building off of the previous example from [Extended Installation](#extended-installation), you now have a user in Laravel Auth (since `Auth::login` was called in the success callback).  With the user model, you can update the user's `updated_at` field.  The callback should call the closure, `$next($request);` and return it.  In this case, the default implementation does this, so in this example, the parent is called.

#### Custom Redirect

As of version 0.6.0, there was added the possibility to customize the redirect method.  For example, if the session token has expired, but the user is still authenticated with Laravel, it can be handled with this example check:

```php
<?php

namespace App\Http\Middleware;

use RootInc\LaravelAzureMiddleware\Azure as Azure;

use Auth;

class AzureAuthentication extends Azure
{
    protected function redirect($request)
    {
        if (Auth::user() !== null)
        {
            return $this->azure($request);
        }
        else
        {
            return parent::redirect($request);
        }
    }
}
```

#### Different Login Route

As of version 0.4.0, there was added the possibility ability to change the `$login_route` in the middleware.

Building off [Extended Installation](#extended-installation), in the `AzureAuthentication` class, you can set the `$login_route` to whatever you need.  For example:

```php
<?php

namespace App\Http\Middleware;

use RootInc\LaravelAzureMiddleware\Azure as Azure;

class AzureAuthentication extends Azure
{
    protected $login_route = "/dashboard";
}
```

The above code would now set `$login_route` to `/dashboard`.

#### Getting / Overriding the Azure Route

As of version 0.7.0, there was added the possibility to get the Azure URL. For example, if you need to modify the Azure URL so that it also passed the user's email to Azure as a parmeter.

Building off [Extended Installation](#extended-installation), in the `AzureAuthentication` class, you could do something like this:

```php
<?php

namespace App\Http\Middleware;

use RootInc\LaravelAzureMiddleware\Azure as Azure;

use Auth;

class AzureAuthentication extends Azure
{
    //you can overload this if you need too.
    public function getAzureUrl()
    {
        return $this->baseUrl . config('azure.tenant_id') . $this->route2 . "authorize?response_type=code&client_id=" . config('azure.client.id') . "&domain_hint=" . urlencode(config('azure.domain_hint')) . "&scope=" . urldecode(config('azure.scope'));
    }

    public function azure(Request $request)
    {
        $user = Auth::user();

        $away = $this->getAzureUrl();

        if ($user)
        {
            $away .= "&login_hint=" . $user->email;
        }

        return redirect()->away($away);
    }
}
```

#### Using in a Multi-Tenanted Application

If the desired use case requires a multi-tenanted application you can simply provide `common` in the .env file instead of a Tenant ID. eg. `AZURE_TENANT_ID=common`.

This works by sending your end users to the generic login routes provided by Microsoft and for all intents and purposes shouldn't appear any different for development either. It should be known that there some inherent drawbacks to this approach as mentioned by in the MS Dev docs here:
> When a single tenant application validates a token, it checks the signature of the token against the signing keys from the metadata document. This test allows it to make sure the issuer value in the token matches the one that was found in the metadata document.
>Because the /common endpoint doesn’t correspond to a tenant and isn’t an issuer, when you examine the issuer value in the metadata for /common it has a templated URL instead of an actual value...

Additional information regarding this can be found [here](https://docs.microsoft.com/en-us/azure/active-directory/develop/howto-convert-app-to-be-multi-tenant#update-your-code-to-handle-multiple-issuer-values).

## Testing with Laravel Azure Middleware

As of version 0.7.0, there was added integration with Laravel's tests by calling `actingAs` for HTTP tests or `loginAs` with Dusk.  This assumes that you are using the `Auth::login` method in the success callback, shown at [Extended Installation](#extended-installation).  There is no need to do anything in the `AzureAuthentication` class, unless you needed to overwrite the default behavior, which is shown below:

```php
<?php

namespace App\Http\Middleware;

use RootInc\LaravelAzureMiddleware\Azure as Azure;

use Auth;

class AzureAuthentication extends Azure
{
    //this is the default behavior
    //overwrite to meet your needs
    protected function handleTesting(Request $request, Closure $next)
    {
        $user = Auth::user();

        if (!isset($user))
        {
            return $this->redirect($request, $next);
        }

        return $this->handlecallback($request, $next, null, null);
    }
}
```

The above will call the class's redirect method, if it can't find a user in Laravel's auth.  Otherwise, the above will call the class's handlecallback method.  Therefore, tests can check if the correct redirection is happening, or that handlecallback is working correctly (which by default calls `$next($request);`).

## Contributing

Thank you for considering contributing to the Laravel Azure Middleware! To encourage active collaboration, the project encourages you to make pull requests, not just issues.

If you file an issue, the issue should contain a title and a clear description of the issue. You should also include as much relevant information as possible and a code sample that demonstrates the issue. The goal of a issue is to make it easy for yourself - and others - to replicate the bug and develop a fix.

## License

The Laravel Azure Middleware is open-sourced software licensed under the [MIT license](http://opensource.org/licenses/MIT).
