<?php
// File: /var/www/html/ns-api/Controller/AuthorizeController.php

class AuthorizeController extends AppController
{
    // Define models.
    public $uses = array('Subscriber', 'Oauthclient', 'Oauthcode', 'Domain');

    public function beforeFilter() {
        parent::beforeFilter();
        // Allow access to the login form without a token
        if (isset($this->Auth)) {
            $this->Auth->allow('index');
        }
    }

    public function index()
    {
        $this->autoRender = false;
        $this->response->type('html');

        // 1. COLLECT PARAMS (Directly from URL/POST)
        $params = array_merge($this->request->query, $this->request->data);

        $clientId     = isset($params['client_id']) ? $params['client_id'] : null;
        $redirectUri  = isset($params['redirect_uri']) ? $params['redirect_uri'] : null;
        $state        = isset($params['state']) ? $params['state'] : null;
        $scope        = isset($params['scope']) ? $params['scope'] : 'Login';
        $responseType = isset($params['response_type']) ? $params['response_type'] : 'code';

        $error = null;

        // 2. VALIDATE BASIC OAUTH PARAMS EXIST
        if (!$clientId || !$redirectUri) {
            header('HTTP/1.0 400 Bad Request');
            die("Error: Missing 'client_id' or 'redirect_uri' in URL parameters.");
        }

        // 3. SECURITY: Validate Client & Redirect URI against Database
        // This ensures the client_id is valid and prevents Open Redirect attacks
        if (!isset($this->Oauthclient)) $this->loadModel('Oauthclient');

        $clientDb = $this->Oauthclient->find('first', array(
            'conditions' => array('client_id' => $clientId),
            'recursive' => -1
        ));

        // If client_id doesn't exist in the database
        if (!$clientDb) {
            header('HTTP/1.0 400 Bad Request');
            die("Invalid Client Application: The provided client_id was not found.");
        }

        // Verify the Redirect URI matches the database record
        $registeredUri = isset($clientDb['Oauthclient']['redirect_uri']) ?
                         $clientDb['Oauthclient']['redirect_uri'] : null;

        if (!empty($registeredUri)) {
            // Strict comparison
            if ($registeredUri !== $redirectUri) {
                header('HTTP/1.0 400 Bad Request');
                die("Error: The redirect_uri provided does not match the registered URI for this client_id.");
            }
        }

        // 4. HANDLE LOGIN SUBMISSION (POST)
        if ($this->request->is('post') && isset($params['username']) && isset($params['password'])) {

            $infoUser = array(
                'username' => $params['username'],
                'password' => $params['password']
            );

            // Verify Credentials
            if ($this->checkUserCredentials($infoUser, 'portal')) {

                // --- SCOPE ELEVATION ---
                // Fetch the user's real permissions from the DB
                if (!isset($this->Subscriber)) $this->loadModel('Subscriber');

                try {
                    $userDb = $this->Subscriber->find('first', array(
                        'conditions' => array(
                            'OR' => array(
                                'subscriber_login' => $params['username'],
                                'email_address' => $params['username']
                            )
                        ),
                        'fields' => array('scope'),
                        'recursive' => -1
                    ));

                    if (!empty($userDb) && isset($userDb['Subscriber']['scope'])) {
                        $scope = $userDb['Subscriber']['scope'];
                    }
                } catch (Exception $e) {
                    // Fail gracefully on DB error
                }

                // --- GENERATE CODE ---
                if (!isset($this->Oauthcode)) $this->loadModel('Oauthcode');

                $authCode = $this->Oauthcode->createAuthCode(
                    $clientId,
                    $redirectUri,
                    $scope,
                    null,
                    false,
                    $params['username']
                );

                Cache::config('_auth_code_', array('duration' => Configure::read('NsAuthCodeExpire')));
                Cache::write(strtolower($params['username']), $authCode, '_auth_code_');

                // --- REDIRECT ---
                $queryStr = http_build_query([
                    'code' => $authCode,
                    'username' => $params['username'], // Passing username back for token exchange
                    'state' => $state
                ]);

                $separator = (strpos($redirectUri, '?') === false) ? '?' : '&';
                $callbackUrl = $redirectUri . $separator . $queryStr;

                $this->redirect($callbackUrl);
                return;

            } else {
                $error = "Invalid Username or Password";
            }
        }

        // 5. RENDER LOGIN FORM
        ?>
        <!DOCTYPE html>
        <html>
        <head>
            <title>Authorize Application</title>
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; display: flex; justify-content: center; padding-top: 50px; background: #f0f2f5; color: #1c1e21; }
                .login-box { background: white; padding: 40px; border-radius: 8px; box-shadow: 0 4px 12px rgba(0,0,0,0.15); width: 320px; }
                h3 { text-align: center; margin-top: 0; color: #1c1e21; }
                input { width: 100%; padding: 12px; margin: 8px 0 20px 0; border: 1px solid #dddfe2; border-radius: 6px; box-sizing: border-box; font-size: 16px; }
                input:focus { border-color: #1877f2; outline: none; box-shadow: 0 0 0 2px #e7f3ff; }
                label { font-size: 14px; font-weight: bold; color: #606770; }
                button { width: 100%; padding: 12px; background: #1877f2; color: white; border: none; border-radius: 6px; font-size: 16px; font-weight: bold; cursor: pointer; transition: background 0.2s; }
                button:hover { background: #166fe5; }
                .error { background: #ffebe8; color: #c00; padding: 10px; border-radius: 4px; border: 1px solid #dd3c10; font-size: 14px; margin-bottom: 15px; text-align: center; }
            </style>
        </head>
        <body>
            <div class="login-box">
                <h3>Authorize Access</h3>

                <?php if($error): ?>
                    <div class="error"><?php echo htmlspecialchars($error); ?></div>
                <?php endif; ?>

                <form method="POST">
                    <!-- Hidden fields to preserve OAuth params -->
                    <input type="hidden" name="client_id" value="<?php echo htmlspecialchars($clientId); ?>">
                    <input type="hidden" name="redirect_uri" value="<?php echo htmlspecialchars($redirectUri); ?>">
                    <input type="hidden" name="state" value="<?php echo htmlspecialchars($state); ?>">
                    <input type="hidden" name="scope" value="<?php echo htmlspecialchars($scope); ?>">
                    <input type="hidden" name="response_type" value="<?php echo htmlspecialchars($responseType); ?>">

                    <label>Username</label>
                    <input type="text" name="username" placeholder="user@domain.com" required autofocus autocomplete="username">

                    <label>Password</label>
                    <input type="password" name="password" placeholder="Password" required autocomplete="current-password">

                    <button type="submit">Log In</button>
                </form>
            </div>
        </body>
        </html>
        <?php
        exit;
    }
}
