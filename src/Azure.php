<?php

namespace RootInc\LaravelAzureMiddleware;

use Closure;

use Illuminate\Http\Request;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;

use Auth;

class Azure
{
    protected $login_route = "/login";

    protected $baseUrl = "https://login.microsoftonline.com/";

    protected $route2 = "/oauth2/v2.0/";
    protected $route = "/oauth2/";

    /**
     * Handle an incoming request
     *
     * @param \Illuminate\Http\Request $request
     * @param Closure $next
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector|mixed
     * @throws \Exception
     */
    public function handle($request, Closure $next)
    {
        $access_token = $request->session()->get('_rootinc_azure_access_token');
        $refresh_token = $request->session()->get('_rootinc_azure_refresh_token');

        if (config('app.env') === "testing")
        {
            return $this->handleTesting($request, $next, $access_token, $refresh_token);
        }

        if (!$access_token || !$refresh_token)
        {
            return $this->redirect($request);
        }

        $client = new Client();

        try {
            $response = $client->request('POST', $this->baseUrl . env('AZURE_TENANT_ID') . $this->route . "token", [
                'form_params' => [
                    'grant_type' => 'refresh_token',
                    'client_id' => env('AZURE_CLIENT_ID'),
                    'client_secret' => env('AZURE_CLIENT_SECRET'),
                    'refresh_token' => $refresh_token,
                    'resource' => env('AZURE_RESOURCE'),
                ]
            ]);

            $contents = json_decode($response->getBody()->getContents());
        } catch(RequestException $e) {
            $this->fail($request, $e);
        }

        $request->session()->put('_rootinc_azure_access_token', $contents->access_token);
        $request->session()->put('_rootinc_azure_refresh_token', $contents->refresh_token);

        return $this->handlecallback($request, $next, $access_token, $refresh_token);
    }

    /**
     * Handle an incoming request in a testing environment
     * Assumes tester is calling actingAs or loginAs during testing to run this correctly
     *
     * @param \Illuminate\Http\Request $request
     * @param Closure $next
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector|mixed
     */
    protected function handleTesting(Request $request, Closure $next)
    {
        $user = Auth::user();

        if (!isset($user))
        {
            return $this->redirect($request, $next);
        }

        return $this->handlecallback($request, $next, null, null);
    }

    /**
     * Gets the azure url
     *
     * @return String
     */
    public function getAzureUrl()
    {
        return $this->baseUrl . env('AZURE_TENANT_ID') . $this->route2 . "authorize?response_type=code&client_id=" . env('AZURE_CLIENT_ID') . "&domain_hint=" . urlencode(env('AZURE_DOMAIN_HINT')) . "&scope=" . urldecode(env('AZURE_SCOPE'));
    }

    /**
     * Redirects to the Azure route.  Typically used to point a web route to this method.
     * For example: Route::get('/login/azure', '\RootInc\LaravelAzureMiddleware\Azure@azure');
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector|mixed
     */
    public function azure(Request $request)
    {
        return redirect()->away( $this->getAzureUrl() );
    }

    /**
     * Customized Redirect method
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector|mixed
     */
    protected function redirect(Request $request)
    {
        return redirect($this->login_route);
    }

    /**
     * Callback after login from Azure
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector|mixed
     * @throws \Exception
     */
    public function azurecallback(Request $request)
    {
        $client = new Client();

        $code = $request->input('code');

        try {
            $response = $client->request('POST', $this->baseUrl . env('AZURE_TENANT_ID') . $this->route . "token", [
                'form_params' => [
                    'grant_type' => 'authorization_code',
                    'client_id' => env('AZURE_CLIENT_ID'),
                    'client_secret' => env('AZURE_CLIENT_SECRET'),
                    'code' => $code,
                    'resource' => env('AZURE_RESOURCE'),
                ]
            ]);

            $contents = json_decode($response->getBody()->getContents());
        } catch(RequestException $e) {
            return $this->fail($request, $e);
        }

        $access_token = $contents->access_token;
        $refresh_token = $contents->refresh_token;
        $profile = json_decode( base64_decode( explode(".", $contents->id_token)[1]) );

        $request->session()->put('_rootinc_azure_access_token', $access_token);
        $request->session()->put('_rootinc_azure_refresh_token', $refresh_token);

        return $this->success($request, $access_token, $refresh_token, $profile);
    }

    /**
     * Handler that is called when a successful login has taken place for the first time
     *
     * @param \Illuminate\Http\Request $request
     * @param String $access_token
     * @param String $refresh_token
     * @param mixed $profile
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector|mixed
     */
    protected function success(Request $request, $access_token, $refresh_token, $profile)
    {
        return redirect()->intended("/");
    }

    /**
     * Handler that is called when a failed handshake has taken place
     *
     * @param \Illuminate\Http\Request $request
     * @param \GuzzleHttp\Exception\RequestException $e
     * @return string
     */
    protected function fail(Request $request, RequestException $e)
    {
        return implode("", explode(PHP_EOL, $e->getMessage()));
    }

    /**
     * Handler that is called every request when a user is logged in
     *
     * @param \Illuminate\Http\Request $request
     * @param Closure $next
     * @param String $access_token
     * @param String $refresh_token
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector|mixed
     */
    protected function handlecallback(Request $request, Closure $next, $access_token, $refresh_token)
    {
        return $next($request);
    }

    /**
     * Gets the logout url
     *
     * @return String
     */
    public function getLogoutUrl()
    {
        return $this->baseUrl . "common" . $this->route . "logout";
    }

    /**
     * Redirects to the Azure logout route.  Typically used to point a web route to this method.
     * For example: Route::get('/logout/azure', '\RootInc\LaravelAzureMiddleware\Azure@azurelogout');
     *
     * @param \Illuminate\Http\Request $request
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector|mixed
     */
    public function azurelogout(Request $request)
    {
        $request->session()->pull('_rootinc_azure_access_token');
        $request->session()->pull('_rootinc_azure_refresh_token');

        return redirect()->away($this->getLogoutUrl());
    }
}
