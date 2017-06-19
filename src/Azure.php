<?php

namespace \RootInc\LaravelAzureMiddleware;

use Closure;

use Illuminate\Http\Request;

use App\User;

use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;

class Azure
{
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
        $access_token = $request->session()->get('access_token');
        $refresh_token = $request->session()->get('refresh_token');

        if (!$access_token || !$refresh_token)
        {
            return redirect("/login");
        }

        $client = new Client();

        try {
            $response = $client->request('POST', $this->baseUrl . env('TENANT_ID') . $this->route . "token", [
                'form_params' => [
                    'grant_type' => 'refresh_token',
                    'client_id' => env('CLIENT_ID'),
                    'client_secret' => env('CLIENT_SECRET'),
                    'refresh_token' => $refresh_token
                ]
            ]);

            $contents = json_decode($response->getBody()->getContents());
        } catch(RequestException $e) {
            return implode("", explode(PHP_EOL,$e->getMessage()));
        }

        $request->session()->put('access_token', $contents->access_token);
        $request->session()->put('refresh_token', $contents->refresh_token);

        return $next($request);
    }

    public function azure(Request $request)
    {
        return redirect()->away( $this->baseUrl . env('TENANT_ID') . $this->route . "authorize?response_type=code&client_id=" . env('CLIENT_ID') . "&resource=" . urlencode(env('RESOURCE')) );
    }

    public function azurecallback(Request $request)
    {
        $client = new Client();

        $code = $request->input('code');

        try {
            $response = $client->request('POST', $this->baseUrl . env('TENANT_ID') . $this->route . "token", [
                'form_params' => [
                    'grant_type' => 'authorization_code',
                    'client_id' => env('CLIENT_ID'),
                    'client_secret' => env('CLIENT_SECRET'),
                    'code' => $code
                ]
            ]);

            $contents = json_decode($response->getBody()->getContents());
        } catch(RequestException $e) {
            return $this->fail($e);
        }

        $access_token = $contents->access_token;
        $refresh_token = $contents->refresh_token;
        $profile = json_decode( base64_decode( explode(".", $contents->id_token)[1]) );

        $request->session()->put('access_token', $access_token);
        $request->session()->put('refresh_token', $refresh_token);

        return $this->success($request, $access_token, $refresh_token, $profile);
    }

    protected function success($request, $access_token, $refresh_token, $profile)
    {
        $email = strtolower($profile->unique_name);

        $user = User::updateOrCreate(['email' => $email], [
            'firstName' => $profile->given_name,
            'lastName' => $profile->family_name
        ]);

        $request->session()->put('user_id', $user->id);

        return redirect("/");
    }

    protected function fail(Request $request, RequestExcpetion $e)
    {
        return implode("", explode(PHP_EOL,$e->getMessage()));
    }
}
