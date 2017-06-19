# Laravel Azure Middleware

Provides Azure Authentication Middleware for a Laravel App.

## Installation

1. `composer require rootinc/laravel-azure-middleware`
2. In our routes folder (most likely `web.php`), add ```Route::get('/login/azure', '\RootInc\LaravelAzureMiddleware\Azure@azure');Route::get('/login/azurecallback', '\RootInc\LaravelAzureMiddleware\Azure@azurecallback');```
3. In our `App\Http\Kernel.php` add `'azure' => \RootInc\LaravelAzureMiddleware\Azure::class,` most likely to the `$routeMiddleware` array.
4. In our `.env` add `TENANT_ID, CLIENT_ID, CLIENT_SECRET and RESOURCE`.  We can get these values/read more here: https://portal.azure.com/
5. Add the `azure` middleware to your route groups (or wherever) and enjoy :tada:

## Routing
`Route::get('/login/azure', '\RootInc\LaravelAzureMiddleware\Azure@azure');` First parameter can be wherever you want to route the azure login.  Change as you would like.
`Route::get('/login/azurecallback', '\RootInc\LaravelAzureMiddleware\Azure@azurecallback');` First parameter can be whatever you want to route after your callback.  Change as you would like.

## Front End

It's best to have an Office 365 button on our login webpage that routes to `/login/azure` (or whatever you renamed it to).  This can be as simple as an anchor tag like this `<a href="/login/azure" class="officeButton"></a>` 

## Contributing

TODO

## License

The Laravel Azure Middleware is open-sourced software licensed under the [MIT license](http://opensource.org/licenses/MIT).
