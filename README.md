# Laravel Azure Middleware

Provides Azure Authentication Middleware for a Laravel App.  If you like this, checkout <a href="https://github.com/rootinc/laravel-saml2-middleware">Laravel Saml Middleware</a>

## Normal Installation

1. `composer require rootinc/laravel-azure-middleware`
2. run `php artisan vendor:publish --provider="RootInc\LaravelAzureMiddleware\AzureServiceProvider"` to install config file to `config/azure.php`
3. In our routes folder (most likely `web.php`), add
```php
Route::get('/login/azure', '\RootInc\LaravelAzureMiddleware\Azure@azure');
Route::get('/login/azurecallback', '\RootInc\LaravelAzureMiddleware\Azure@azurecallback');
```

4. In our `App\Http\Kernel.php` add `'azure' => \RootInc\LaravelAzureMiddleware\Azure::class,` most likely to the `$routeMiddleware` array.
5. In our `.env` add `AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET and AZURE_RESOURCE`.  We can get these values/read more here: https://portal.azure.com/ (Hint: AZURE_RESOURCE should be https://graph.microsoft.com)
6. As of 0.8.0, we added `AZURE_SCOPE`, which are permissions to be used for the request.  We can read more about these here: https://docs.microsoft.com/en-us/graph/api/resources/users?view=graph-rest-1.0
7. We also added an optional `AZURE_DOMAIN_HINT` that can be used to help users know which email address they should login with.  More info here: https://azure.microsoft.com/en-us/updates/app-service-auth-and-azure-ad-domain-hints/
8. Within our app on https://portal.azure.com/ point `reply url` to the `/login/azurecallback` route with the full url (ex: http://thewebsite.com/login/azurecallback).
9. Add the `azure` middleware to your route groups on any routes that needs protected by auth and enjoy :tada:
10. If you need custom callbacks, see [Extended Installation](#extended-installation).

__NOTE: ~~You may need to add premissions for (legacy) Azure Active Directory Graph~~ As of 0.8.0, we are using v2 of Azure's login API, which allows us to pass scopes, or permissions we'd like to use.__

## Routing

`Route::get('/login/azure', '\RootInc\LaravelAzureMiddleware\Azure@azure');` First parameter can be wherever you want to route the azure login.  Change as you would like.

`Route::get('/login/azurecallback', '\RootInc\LaravelAzureMiddleware\Azure@azurecallback');` First parameter can be whatever you want to route after your callback.  Change as you would like.

`Route::get('/logout/azure', '\RootInc\LaravelAzureMiddleware\Azure@azurelogout');` First parameter can be whatever you want to route after your callback.  Change as you would like.

### Front End

It's best to have an Office 365 button on your login webpage that routes to `/login/azure` (or whatever you renamed it to).  This can be as simple as an anchor tag like this `<a href="/login/azure" class="officeButton"></a>` 

## Extended Installation

The out-of-the-box implementation let's you login users.  However, let's say we would like to store this user into a database, as well as login the user in with Laravel Auth.  There are two callbacks that are recommended to extend from the Azure class called `success` and `fail`. The following provides information on how to extend the Root Laravel Azure Middleware Library:

1. To get started (assuming we've followed the [Normal Installation](#normal-installation) directions), create a file called `AppAzure.php` in the `App\Http\Middleware` folder.  You can either do this through `artisan` or manually.
2. Add this as a starting point in this file:

```php
<?php

namespace App\Http\Middleware;

use RootInc\LaravelAzureMiddleware\Azure as Azure;
use Microsoft\Graph\Graph;
use Microsoft\Graph\Model;

use Auth;

use App\User;

class AppAzure extends Azure
{
    protected function success($request, $access_token, $refresh_token, $profile)
    {
        $graph = new Graph();
        $graph->setAccessToken($access_token);
        
        $graph_user = $graph->createRequest("GET", "/me")
                      ->setReturnType(Model\User::class)
                      ->execute();
        
        $email = strtolower($graph_user->getUserPrincipalName());

        $user = User::updateOrCreate(['email' => $email], [
            'firstName' => $graph_user->getGivenName(),
            'lastName' => $graph_user->getSurname(),
        ]);

        Auth::login($user, true);

        return parent::success($request, $access_token, $refresh_token, $profile);
    }
}
```

The above gives us a way to add/update users after a successful handshake.  `$profile` contains all sorts of metadata that we use to create or update our user.  More information here: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-oauth-code#jwt-token-claims . The default implementation redirects to the intended url, or `/`, so we call the parent here.  Feel free to not extend the default and to redirect elsewhere.

3. Our routes need to be updated to the following:

```php
Route::get('/login/azure', '\App\Http\Middleware\AppAzure@azure');
Route::get('/login/azurecallback', '\App\Http\Middleware\AppAzure@azurecallback');
Route::get('/logout/azure', '\App\Http\Middleware\AppAzure@azurelogout');
```

4. Finally, update `Kernel.php`'s `azure` key to be `'azure' => \App\Http\Middleware\AppAzure::class,`

## Other Extending Options

#### Callback on Every Handshake

As of v0.4.0, we added a callback after every successful request (handshake) from Azure.  The default is to simply call the `$next` closure.  However, let's say we want to update the user.  Here's an example of how to go about that:

```php
<?php

namespace App\Http\Middleware;

use Closure;

use RootInc\LaravelAzureMiddleware\Azure as Azure;

use Auth;
use Carbon\Carbon;

use App\User;

class AppAzure extends Azure
{
    protected function handlecallback($request, Closure $next, $access_token, $refresh_token)
    {
        $user = Auth::user();

        $user->updated_at = Carbon::now();

        $user->save();

        return parent::handlecallback($request, $next, $access_token, $refresh_token);
    }
}
```

Building off of our previous example from [Extended Installation](#extended-installation), we have a user in the Auth now (since we did `Auth::login` in the success callback).  With the user model, we can update the user's `updated_at` field.  The callback should call the closure, `$next($request);` and return it.  In our case, the default implementation does this, so we call the parent here.

#### Custom Redirect

As of v0.6.0, we added the ability to customize the redirect method.  For example, if the session token's expire, but the user is still authenticated with Laravel, we can check for that with this example:

```php
<?php

namespace App\Http\Middleware;

use RootInc\LaravelAzureMiddleware\Azure as Azure;

use Auth;

class AppAzure extends Azure
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

As of v0.4.0, we added the ability to change the `$login_route` in the middleware.  Building off [Extended Installation](#extended-installation), in our `AppAzure` class, we can simply set `$login_route` to whatever.  For example:

```php
<?php

namespace App\Http\Middleware;

use RootInc\LaravelAzureMiddleware\Azure as Azure;

class AppAzure extends Azure
{
    protected $login_route = "/";
}
```

The above would now set `$login_route` to `/` or root.

#### Getting / Overriding the Azure Route

As of v0.7.0, we added the ability to get the Azure URL.  For example, let's say we wanted to modify the Azure URL so that it also passed the user's email to Azure as a parmater.  Building off [Extended Installation](#extended-installation), in our `AppAzure` class, we could do something like this:

```php
<?php

namespace App\Http\Middleware;

use RootInc\LaravelAzureMiddleware\Azure as Azure;

use Auth;

class AppAzure extends Azure
{
    //we could overload this if we wanted too.
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

As of v0.7.0, we added integration with Laravel's tests by calling `actingAs` for HTTP tests or `loginAs` with Dusk.  This assumes that we are using the `Auth::login` method in the success callback, shown at [Extended Installation](#extended-installation).  There is no need to do anything in our `AppAzure` class, unless we needed to overwrite the default behavior, which is shown below:

```php
<?php

namespace App\Http\Middleware;

use RootInc\LaravelAzureMiddleware\Azure as Azure;

use Auth;

class AppAzure extends Azure
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

Thank you for considering contributing to the Laravel Azure Middleware! To encourage active collaboration, we encourage pull requests, not just issues.

If you file an issue, the issue should contain a title and a clear description of the issue. You should also include as much relevant information as possible and a code sample that demonstrates the issue. The goal of a issue is to make it easy for yourself - and others - to replicate the bug and develop a fix.

## License

The Laravel Azure Middleware is open-sourced software licensed under the [MIT license](http://opensource.org/licenses/MIT).
