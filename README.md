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
4. In our `.env` add `TENANT_ID, CLIENT_ID, CLIENT_SECRET and RESOURCE`.  We can get these values/read more here: https://portal.azure.com/
5. Add the `azure` middleware to your route groups (or wherever) and enjoy :tada:
6. If you need custom callbacks, see #Extended Installation.

## Routing

`Route::get('/login/azure', '\RootInc\LaravelAzureMiddleware\Azure@azure');` First parameter can be wherever you want to route the azure login.  Change as you would like.

`Route::get('/login/azurecallback', '\RootInc\LaravelAzureMiddleware\Azure@azurecallback');` First parameter can be whatever you want to route after your callback.  Change as you would like.

## Front End

It's best to have an Office 365 button on our login webpage that routes to `/login/azure` (or whatever you renamed it to).  This can be as simple as an anchor tag like this `<a href="/login/azure" class="officeButton"></a>` 

## Extended Installation

The out-of-the-box implementation let's you login users.  However, let's say we would like to store this user into a database.  There are two callbacks that are recommended to extend from the Azure class called `success` and `fail`. The following provides information on how to extend the Root Laravel Azure Middleware Library:

1. To get started (assuming we've followed the #Normal Installation directions), create a file called `AppAzure.php` in the `App\Http\Middleware` folder.  You can either do this through `artisan` or manually.
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

## Contributing

TODO

## License

The Laravel Azure Middleware is open-sourced software licensed under the [MIT license](http://opensource.org/licenses/MIT).
