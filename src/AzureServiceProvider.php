<?php

namespace RootInc\LaravelAzureMiddleware;

use Illuminate\Support\ServiceProvider;

class AzureServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     *
     * @return void
     */
    public function boot()
    {
        if ($this->app->runningInConsole())
        {
            $this->publishes([
                __DIR__ . '/../config/azure.php' => config_path('azure.php'),
            ], 'config');
        }
    }

     /**
     * {@inheritdoc}
     */
    public function register()
    {
        $this->mergeConfigFrom(
            __DIR__ . '/../config/azure.php', 'azure'
        );
    }
}