<?php
// File: /var/www/html/ns-api/Controller/AuthorizeController.php

class AuthorizeController extends AppController
{
    // Load the same models used by Oauth2Controller
    public $uses = array('Subscriber', 'Oauthclient', 'Oauthcode', 'Domain');

    public function beforeFilter() {
        parent::beforeFilter();
        // Allow access to this controller without a prior token
        if (isset($this->Auth)) {
            $this->Auth->allow('index');
        }
    }

    public function index()
    {
        // Disable the default CakePHP view rendering so we can echo HTML directly
        $this->autoRender = false;
        $this->response->type('html');

        // 1. COLLECT PARAMS (Support both GET and POST)
        $params = array_merge($this->request->query, $this->request->data);

        $clientId     = isset($params['client_id']) ? $params['client_id'] : null;
        $redirectUri  = isset($params['redirect_uri']) ? $params['redirect_uri'] : null;
        $state        = isset($params['state']) ? $params['state'] : null;
        $scope        = isset($params['scope']) ? $params['scope'] : 'Login';
        $responseType = isset($params['response_type']) ? $params['response_type'] : 'code';

        $error = null;

        // 2. VALIDATE BASIC OAUTH PARAMS
        if (!$clientId || !$redirectUri) {
            die("Error: Missing client_id or redirect_uri.");
        }

        // --- START SECURITY FIX: Validate Redirect URI ---

        // Lookup the client in the database
        $clientDb = $this->Oauthclient->find('first', array(
            'conditions' => array('client_id' => $clientId),
            'recursive' => -1
        ));

        if (!$clientDb) {
            // Obscure error message for security (don't reveal valid/invalid IDs)
            header('HTTP/1.0 400 Bad Request');
            die("Invalid Client Application");
        }

        // NetSapiens stores the URI in 'redirect_uri'.
        // Note: Check your specific DB schema if this key differs,
        // but it aligns with the 'createClient' method in the original file.
        $registeredUri = isset($clientDb['Oauthclient']['redirect_uri']) ?
                         $clientDb['Oauthclient']['redirect_uri'] : null;

        // If the client has a registered URI, we MUST enforce it.
        if (!empty($registeredUri)) {
            // Strict match is best security
            if ($registeredUri !== $redirectUri) {
                header('HTTP/1.0 400 Bad Request');
                die("Error: The redirect_uri provided does not match the registered URI for this client.");
            }
        }
        // If $registeredUri is empty/null in the DB, you might choose to
        // allow the URL argument (Development mode) or block it (Strict Production).
        // I recommend blocking it if possible:
        else {
             die("Error: No redirect URI is registered for this client.");
        }

        // 3. HANDLE LOGIN SUBMISSION (POST)
        if ($this->request->is('post') && isset($params['username']) && isset($params['password'])) {

            $infoUser = array(
                'username' => $params['username'],
                'password' => $params['password']
            );
            // Use the AppController's existing credential check
            if ($this->checkUserCredentials($infoUser, 'portal')) {

                // A. LOGIN SUCCESS - GENERATE CODE
                $authCode = $this->Oauthcode->createAuthCode(
                    $clientId,
                    $redirectUri,
                    $scope,
                    null,
                    false,
                    $params['username']
                );

                // Cache the code (Required by Oauth2Controller logic)
                // Note: The key is the lowercased username.
                Cache::config('_auth_code_', array('duration' => Configure::read('NsAuthCodeExpire')));
                Cache::write(strtolower($params['username']), $authCode, '_auth_code_');

                // B. REDIRECT BACK TO APPLICATION
                $queryStr = http_build_query([
                    'code' => $authCode,
                    'username' => $params['username'],
                    'state' => $state
                ]);

                // Handle existing query params in redirect_uri
                $separator = (strpos($redirectUri, '?') === false) ? '?' : '&';
                $callbackUrl = $redirectUri . $separator . $queryStr;

                $this->redirect($callbackUrl);
                return;

            } else {
                $error = "Invalid Username or Password";
            }

        }

        // 4. RENDER LOGIN FORM (GET or Failed POST)
        // We echo HTML directly to avoid creating a .ctp file in the View folder
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authorize Application</title>
            <style>
                body { font-family: sans-serif; display: flex; justify-content: center; padding-top: 50px; background: #f4f4f4; }
                .login-box { background: white; padding: 30px; border-radius: 5px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); width: 300px; }
                input { width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box; }
                button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 3px; cursor: pointer; }
                button:hover { background: #0056b3; }
                .error { color: red; font-size: 0.9em; margin-bottom: 10px; }
            </style>
        </head>
        <body>
            <div class="login-box">
                <h3 style="text-align:center;">Login</h3>
                <?php if($error): ?><div class="error"><?php echo htmlspecialchars($error); ?></div><?php endif; ?>

                <form method="POST">
                    <!-- Pass OAuth params through as hidden fields -->
                    <input type="hidden" name="client_id" value="<?php echo htmlspecialchars($clientId); ?>">
                    <input type="hidden" name="redirect_uri" value="<?php echo htmlspecialchars($redirectUri); ?>">
                    <input type="hidden" name="state" value="<?php echo htmlspecialchars($state); ?>">
                    <input type="hidden" name="scope" value="<?php echo htmlspecialchars($scope); ?>">
                    <input type="hidden" name="response_type" value="<?php echo htmlspecialchars($responseType); ?>">

                    <label>Username</label>
                    <input type="text" name="username" required autofocus>

                    <label>Password</label>
                    <input type="password" name="password" required>

                    <button type="submit">Authorize</button>
                </form>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
}
