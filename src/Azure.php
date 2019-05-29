<?php

namespace RootInc\LaravelAzureMiddleware;

use Closure;

use Illuminate\Http\Request;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;

class Azure
{
    protected $login_route = "/login";

    protected $baseUrl = "https://login.microsoftonline.com/";
    protected $route = "/oauth2/";

    /**
     * Handle an incoming request
     *
     * @param $request
     * @param Closure $next
     * @return \Illuminate\Http\RedirectResponse|\Illuminate\Routing\Redirector|mixed
     * @throws \Exception
     */
    public function handle($request, Closure $next)
    {
        $access_token = $request->session()->get('_rootinc_azure_access_token');
        $refresh_token = $request->session()->get('_rootinc_azure_refresh_token');

        if (env("APP_ENV") === "testing")
        {
            return $this->handlecallback($request, $next, $access_token, $refresh_token);
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
                    'refresh_token' => $refresh_token
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

    public function azure(Request $request)
    {
        return redirect()->away( $this->baseUrl . env('AZURE_TENANT_ID') . $this->route . "authorize?response_type=code&client_id=" . env('AZURE_CLIENT_ID') . "&resource=" . urlencode(env('AZURE_RESOURCE')) );
    }

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
                    'code' => $code
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

    protected function redirect($request)
    {
        return redirect($this->login_route);
    }

    protected function success($request, $access_token, $refresh_token, $profile)
    {
        return redirect("/");
    }

    protected function fail(Request $request, RequestException $e)
    {
        return implode("", explode(PHP_EOL, $e->getMessage()));
    }

    protected function handlecallback($request, Closure $next, $access_token, $refresh_token)
    {
        return $next($request);
    }
}
