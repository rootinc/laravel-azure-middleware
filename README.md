# Laravel Azure Middleware

Provides Azure Authentication Middleware for a Laravel App.

## Normal Installation

1. `composer require rootinc/laravel-azure-middleware`
2. In our routes folder (most likely `web.php`), add
```php
Route::get('/login/azure', '\RootInc\LaravelAzureMiddleware\Azure@azure');
Route::get('/login/azurecallback', '\RootInc\LaravelAzureMiddleware\Azure@azurecallback');
```

3. In our `App\Http\Kernel.php` add `'azure' => \RootInc\LaravelAzureMiddleware\Azure::class,` most likely to the `$routeMiddleware` array.
4. In our `.env` add `AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET and AZURE_RESOURCE`.  We can get these values/read more here: https://portal.azure.com/
5. Within our app on https://portal.azure.com/ point `reply url` to the `/login/azurecallback` route with the full url (ex: http://thewebsite.com/login/azurecallback).
6. Add the `azure` middleware to your route groups on any routes that needs protected by auth and enjoy :tada:
7. If you need custom callbacks, see [Extended Installation](#extended-installation).

__NOTE: You may need to add premissions for (legacy) Azure Active Directory Graph__

## Routing

`Route::get('/login/azure', '\RootInc\LaravelAzureMiddleware\Azure@azure');` First parameter can be wherever you want to route the azure login.  Change as you would like.

`Route::get('/login/azurecallback', '\RootInc\LaravelAzureMiddleware\Azure@azurecallback');` First parameter can be whatever you want to route after your callback.  Change as you would like.

### Front End

It's best to have an Office 365 button on our login webpage that routes to `/login/azure` (or whatever you renamed it to).  This can be as simple as an anchor tag like this `<a href="/login/azure" class="officeButton"></a>` 

## Extended Installation

The out-of-the-box implementation let's you login users.  However, let's say we would like to store this user into a database.  There are two callbacks that are recommended to extend from the Azure class called `success` and `fail`. The following provides information on how to extend the Root Laravel Azure Middleware Library:

1. To get started (assuming we've followed the [Normal Installation](#normal-installation) directions), create a file called `AppAzure.php` in the `App\Http\Middleware` folder.  You can either do this through `artisan` or manually.
2. Add this as a starting point in this file:

```php
<?php

namespace App\Http\Middleware;

use RootInc\LaravelAzureMiddleware\Azure as Azure;

use App\User;

class AppAzure extends Azure
{
    protected function success($request, $access_token, $refresh_token, $profile)
    {
        $email = strtolower($profile->unique_name);

        $user = User::updateOrCreate(['email' => $email], [
            'firstName' => $profile->given_name,
            'lastName' => $profile->family_name
        ]);

        $request->session()->put('user_id', $user->id);

        return parent::success($request, $access_token, $refresh_token, $profile);
    }
}
```

The above gives us a way to add/update users after a successful handshake.  `$profile` contains all sorts of metadata that we use to create or update our user.  More information here: https://docs.microsoft.com/en-us/azure/active-directory/develop/active-directory-protocols-oauth-code#jwt-token-claims . The default implementation redirects to `/`, so we call the parent here.  Feel free to not extend the default and to redirect elsewhere.

3. Our routes need to be updated to the following:

```php
Route::get('/login/azure', '\App\Http\Middleware\AppAzure@azure');
Route::get('/login/azurecallback', '\App\Http\Middleware\AppAzure@azurecallback');
```

4. Finally, update `Kernel.php`'s `azure` key to be `'azure' => \App\Http\Middleware\AppAzure::class,`

### Callback on Every Handshake

As of v0.4.0, we added a callback after every successful handle (handshake).  The default is to simply call the `$next` closure.  However, let's say we want to store a Singleton of a user.  Here's an example of how to go about that:

```php
<?php

namespace App\Http\Middleware;

use Closure;

use RootInc\LaravelAzureMiddleware\Azure as Azure;

use App\User;

class AppAzure extends Azure
{
    protected function handlecallback($request, Closure $next, $access_token, $refresh_token)
    {
        $user_id = $request->session()->get('user_id');

        if ($user_id)
        {
            $user = User::find($user_id);

            \App::singleton('user', function() use($user){
                return $user;
            });
        }

        return parent::handlecallback($request, $next, $access_token, $refresh_token);
    }
}
```

Building off of our previous example from [Extended Installation](#extended-installation), we have a `user_id` set in the session.  We can use this id to query against the user model.  Once we have the user model, we can setup the singleton to return the user.  The callback should call the closure, `$next($request);` and return it.  In our case, the default implementation redirects to `/`, so we call the parent here.

#### Custom Redirect

As of v0.6.0, we added the ability to customize the redirect method.  For example, if the session token's expire, but the user is still authenticated, we can check for that with this example:

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
            return redirect($this->login_route);
        }
    }
}
```

#### Different Login Route

As of v0.4.0, we added the ability to change the `$login_route` in the middelware.  Building off [Extended Installation](#extended-installation), in our `AppAzure` class, we can simply set `$login_route` to whatever.  For example:

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

## Contributing

Thank you for considering contributing to the Laravel Azure Middleware! To encourage active collaboration, we encourage pull requests, not just issues.

If you file an issue, the issue should contain a title and a clear description of the issue. You should also include as much relevant information as possible and a code sample that demonstrates the issue. The goal of a issue is to make it easy for yourself - and others - to replicate the bug and develop a fix.

## License

The Laravel Azure Middleware is open-sourced software licensed under the [MIT license](http://opensource.org/licenses/MIT).
