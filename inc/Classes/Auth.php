<?php

namespace LanSuite;

use LanSuite\AzDGCrypt;

/**
 * Class auth
 *
 * Authorisation and Cookie management for LanSuite
 *
 * @todo Change uniqkey from md5(password) to an extra Field
 */
class Auth
{

    /**
     * Userdata
     *
     * @var array
     */
    public $auth = [];

    /**
     * Time
     *
     * @var int
     */
    private $timestamp;

    /**
     * Array containing all users, currently online
     *
     * @var array
     */
    public $online_users = [];

    /**
     * Array containing all users, currently online by ajax, but no hit last 10min
     *
     * @var array
     */
    public $away_users = [];

    /**
     * auth constructor.
     * @param string $frmwrkmode Frameworkmode for switch Stats
     */
    public function __construct($frmwrkmode = "")
    {
        global $db;

        $this->auth["sessid"] = session_id();
        $this->auth["ip"] = $_SERVER['REMOTE_ADDR'];
        $this->timestamp = time();

        // Update statistics
        $this->update_visits($frmwrkmode);

        $last10Minutes = $this->timestamp - 60*10;
        $lastMinute = $this->timestamp - 60*1;

        $res = $db->qry(
            'SELECT
                `userid`,
                SUM(IF(`lasthit` > %int%, 1, 0)) AS `online`
            FROM %prefix%stats_auth
            WHERE
                login = "1"
                AND (
                    lasthit > %int%
                    OR lastajaxhit > %int%
                )
                AND userid > 0
            GROUP BY userid',
            $last10Minutes,
            $last10Minutes,
            $lastMinute
        );

        while ($row = $db->fetch_array($res)) {
            // If at the same time a user is logged in twice or multiple times
            // (e.g. via different browsers)
            // the field `online` will be more than 1.
            // But we don't care at this point, because we only care _which_
            // user is logged in  and not how many times.
            // Even if the user is logged in with Chrome, is inactive for more then 10 minutes
            // and the AJAX heartbeat kicks in _and_ the same user is logged in with Safari
            // and there the user is active, it will count as an online user.
            if ($row['online'] > 0) {
                $this->online_users[] = $row['userid'];
            } else {
                $this->away_users[] = $row['userid'];
            }
        }

        // Close sessions older than 1-2 hours.
        // ceil(x / $oneHour) * $oneHour for making query the same for one hour and therefore cacheable by MySQL
        // Do check first, for SELECT is faster than DELETE
        $oneHour = 60 * 60;
        $thirtyDays = 60 * 60 * 24 * 30;
        $row = $db->qry_first('SELECT 1 AS found FROM %prefix%stats_auth WHERE lasthit < %int%', ceil((time() - $oneHour) / $oneHour) * $oneHour);
        if ($row['found']) {
            $db->qry_first('DELETE FROM %prefix%stats_auth WHERE lasthit < %int%', ceil((time() - $oneHour) / $oneHour) * $oneHour);
            $db->qry_first('OPTIMIZE TABLE %prefix%stats_auth');
        }
    }

    /**
     * Check User logon via Session or Cookie.
     * Check some security options and set or delete logon if any problem is found.
     *
     * @return array
     */
    public function check_logon()
    {
        // Possible cases
        // 1. Logged out. No Session. No Cookie
        // 1.5 Session exists, but no cookie
        // 2. No session, but a cookie (session times out)
        // 3. Logged in with session and cookie
        // 4. Logged in with session and cookie and user switch

        // Look for SessionID in DB and load auth-data
        // Not found? Then look for valid cookie
            // Found? Then try cookie login
            // Not Found?: Cookie invalide. But no message, for maybe the user don't likes to log in
        $this->loadAuthBySID();

        return $this->auth;
    }

    /**
     * Check and Login a User.
     *
     * @param string $email
     * @param string $password
     * @param int $show_confirmation
     * @return array
     */
    public function login($raw_email, $password, $show_confirmation = 1)
    {
        global $db, $func, $cfg, $party;

        $email = "";
        if ($raw_email != "") $email = strtolower(htmlspecialchars(trim($raw_email)));

        if ($email == "") {
            $func->information(t('Bitte gib deine E-Mail-Adresse oder deine Lansuite-ID ein.'), '', 1);
        } elseif ($password == "") {
            $func->information(t('Bitte gib dein Kennwort ein.'), '', 1);
        } else {
            $is_email = strstr($email, '@');
            $is_userid = ctype_digit($email);
            if($is_email) {
                $user = $db->qry_first('SELECT *, 1 AS found, 1 AS user_login FROM %prefix%user WHERE (LOWER(email) = %string%)',$email);
            }
            else if($is_userid) {
                $user = $db->qry_first('SELECT *, 1 AS found, 1 AS user_login FROM %prefix%user WHERE (userid = %int%)',$email);
            }
            else {
                $user = $db->qry_first('SELECT *, 1 AS found, 1 AS user_login FROM %prefix%user WHERE (LOWER(username) = %string%)', strtolower($email));
            }

            // Needs to be a seperate query; WHERE (p.party_id IS NULL OR p.party_id=%int%) does not work when 2 parties exist
            if ($func->isModActive('party')) {
                $party_query = $db->qry_first('SELECT p.checkin AS checkin, p.checkout AS checkout FROM %prefix%party_user AS p WHERE p.party_id=%int% AND user_id=%int%', $party->party_id, $user['userid']);
            }

            // Count login errors
            $row = $db->qry_first('SELECT COUNT(*) AS anz
               FROM %prefix%login_errors
               WHERE userid = %int% AND (UNIX_TIMESTAMP(NOW()) - UNIX_TIMESTAMP(time) < 60)
               GROUP BY userid', $user['userid']);

            // Too many login trys?
            if ($row['anz'] >= 5) {
                $func->information(t('Du hast in der letzten Minute bereits 5 mal dein Passwort falsch eingegeben. Bitte warte einen Moment, bevor du es erneut versuchen darfst'), '', 1);

            // Email not found?
            } elseif (!$user["found"]) {
                $func->information(t('Dieser Benutzer existiert nicht in unserer Datenbank. Bitte prüfe die eingegebene Email/ID'), '', 1);
                $func->log_event(t('Falsche Email angegeben (%1)', $tmp_login_email), '2', 'Authentifikation');

            // Account disabled?
            } elseif ($user["type"] <= -1) {
                $func->information(t('Dein Account ist gesperrt. Melde dich bitte bei der Organisation.'), '', 1);
                $func->log_event(t('Login für %1 fehlgeschlagen (Account gesperrt).', $tmp_login_email), "2", "Authentifikation");

            // Account locked?
            } elseif ($user['locked']) {
                $func->information(t('Dieser Account ist noch nicht freigeschaltet. Bitte warte bis ein Organisator dich freigeschaltet hat.'), '', 1);
                $func->log_event(t('Account von %1 ist noch gesperrt. Login daher fehlgeschlagen.', $tmp_login_email), "2", "Authentifikation");

            // Mail not verified?
            } elseif ($cfg['sys_login_verified_mail_only'] == 2 and !$user['email_verified'] and $user["type"] < 2) {
                $func->information(t('Du hast deine Email-Adresse (%1) noch nicht verifiziert. Bitte folge dem Link in der dir zugestellten Email.', $user['email']).' <a href="index.php?mod=usrmgr&action=verify_email&step=2&userid='. $user['userid'] .'">'. t('Klicke hier, um die Mail erneut zu versenden</a>'), '', 1);
                $func->log_event(t('Login fehlgeschlagen. Email (%1) nicht verifiziert', $user['email']), "2", "Authentifikation");

            // User login and wrong password?
            } elseif ($user["user_login"] and !PasswordHash::verify($password, $user["password"])) {
                ($cfg["sys_internet"])? $remindtext = t('Hast du dein Passwort vergessen?<br/><a href="./index.php?mod=usrmgr&action=pwrecover"/>Hier kannst du ein neues Passwort generieren</a>.') : $remindtext = t('Solltest du dein Passwort vergessen haben, wende dich bitte an die Organisation.');
                $func->information(t('Die von dir eingebenen Login-Daten sind fehlerhaft. Bitte überprüfe deine Eingaben.') . HTML_NEWLINE . HTML_NEWLINE . $remindtext, '', 1);
                $func->log_event(t('Login für %1 fehlgeschlagen (Passwort-Fehler).', $tmp_login_email), "2", "Authentifikation");
                $db->qry('INSERT INTO %prefix%login_errors SET userid = %int%, ip = INET6_ATON(%string%)', $user['userid'], $_SERVER['REMOTE_ADDR']);

            // Not checked in?
            } elseif ($func->isModActive('party') and (!$party_query["checkin"] or $party_query["checkin"] == '0000-00-00 00:00:00') and $user["type"] < 2 and !$cfg["sys_internet"]) {
                $func->information(t('Du bist nicht eingecheckt. Im Intranetmodus ist ein Einloggen nur möglich, wenn du eingecheckt bist.') .HTML_NEWLINE. t('Bitte melden dich bei der Organisation.'), '', 1);
                $func->log_event(t('Login für %1 fehlgeschlagen (Account nicht eingecheckt).', $tmp_login_email), "2", "Authentifikation");

            // Already checked out?
            } elseif ($func->isModActive('party') and $party_query["checkout"] and $party_query["checkout"] != '0000-00-00 00:00:00' and $user["type"] < 2 and !$cfg["sys_internet"]) {
                $func->information(t('Du bist bereits ausgecheckt. Im Intranetmodus ist ein Einloggen nur möglich, wenn du eingecheckt bist.') .HTML_NEWLINE. t('Bitte melden dich bei der Organisation.'), '', 1);
                $func->log_event(t('Login für %1 fehlgeschlagen (Account ausgecheckt).', $tmp_login_email), "2", "Authentifikation");

            // Everything fine!
            } else {
                $this->regenerateSessionId();
                if ($user["user_login"] and PasswordHash::needsRehash($user["password"])) {
                    try {
                        $db->qry('UPDATE %prefix%user SET password = %string% WHERE userid = %int%', PasswordHash::hash($password), $user["userid"]);
                        $func->information(t('Es wurde ein Sicherheitsupgrade von deinem Passwort durchgeführt.'), '', 1);
                    } catch (Exception $e) {
                        $func->error(t('Sicherheitsupgrade von deinem Passwort ist fehlgeschlagen!'));
                    }
                }

                // Set Logonstats
                $db->qry('UPDATE %prefix%user SET logins = logins + 1, changedate = changedate, lastlogin = NOW() WHERE userid = %int%', $user['userid']);

                if ($cfg["sys_logoffdoubleusers"]) {
                    $db->qry('DELETE FROM %prefix%stats_auth WHERE userid = %int%', $user['userid']);
                }

                // Set authdata
                $db->qry(
                    'REPLACE INTO %prefix%stats_auth
                  SET sessid = %string%, userid = %int%, login = \'1\', ip = %string%, logtime = %string%, logintime = %string%, lasthit = %string%',
                    $this->auth["sessid"],
                    $user["userid"],
                    $this->auth["ip"],
                    $this->timestamp,
                    $this->timestamp,
                    $this->timestamp
                );

                $this->loadAuthBySID();
                $this->auth['userid'] = $user['userid'];
                if (!in_array($user['userid'], $this->online_users)) {
                    $this->online_users[] = $user['userid'];
                }

                if ($show_confirmation) {
                    // Print Loginmessages
                    if ($_GET['mod']=='auth' and $_GET['action'] == 'login') {
                        $auth_backlink = "index.php?mod=home";
                    } else {
                        $auth_backlink = "";
                    }
                    $func->confirmation(t('Erfolgreich eingeloggt. Die Änderungen werden beim Laden der nächsten Seite wirksam.'), $auth_backlink, '', 'FORWARD');

                    // Show error logins
                    $msg = '';
                    $res = $db->qry('SELECT INET6_NTOA(ip) AS ip, time
                                   FROM %prefix%login_errors
                                   WHERE userid = %int%', $user['userid']);
                    while ($row = $db->fetch_array($res)) {
                        $msg .= t('Am') .' '. $row['time'] .' von der IP: <a href="https://dnsquery.org/ipwhois/'. $row['ip'] .'" target="_blank">'. $row['ip'] .'</a>'. HTML_NEWLINE;
                    }
                    $db->free_result($res);
                    if ($msg != '') {
                        $func->information('<b>'. t('Fehlerhafte Logins') .'</b>'. HTML_NEWLINE .t('Es wurden fehlerhafte Logins seit deinem letzten erfolgreichen Login durchgeführt.'). HTML_NEWLINE . HTML_NEWLINE . $msg, NO_LINK, 1);
                    }
                    $db->qry('DELETE FROM %prefix%login_errors WHERE userid = %int%', $user['userid']);
                }
            }
        }
        $_SESSION['auth'] = $this->auth;
        return $this->auth;
    }

    /**
     * Logout the user and delete Session data, cookie and authdata
     *
     * @return array
     */
    public function logout()
    {
        global $db, $func;

        // Delete entry from SID
        $db->qry('DELETE FROM %prefix%stats_auth WHERE sessid=%string%', $this->auth["sessid"]);
        $this->auth['login'] = "0";

        $this->regenerateSessionId();

        // Reset Sessiondata
        unset($this->auth);
        unset($_SESSION['auth']);
        $this->auth['login'] == "0";
        $this->auth["userid"] = "";
        $this->auth["email"] = "";
        $this->auth["username"] = "";
        $this->auth["userpassword"] = "";
        $this->auth["type"] = 0;

        $func->confirmation(t('Du wurdest erfolgreich ausgeloggt. Vielen dank für deinen Besuch.'), "", 1, 'FORWARD');
        return $this->auth;
    }

    /**
     * Switch to UserID
     * Switches to given UserID and stores a callback function in a Cookie and DB
     *
     * @param $target_id
     * @return void
     */
    public function switchto($target_id)
    {
        global $db, $func;

        // Get target user type
        $target_user = $db->qry_first('SELECT type FROM %prefix%user WHERE userid = %int%', $target_id);

        // Only highlevel to lowerlevel
        if ($this->auth["type"] > $target_user["type"]) {
            // Save old user ID
            $_SESSION['auth']['olduserid'] = $this->auth['userid'];

            // Link session ID to new user ID
            $db->qry('UPDATE %prefix%stats_auth SET userid=%int%, login=\'1\' WHERE sessid=%string%', $target_id, $this->auth["sessid"]);

            $func->confirmation(t('Benutzerwechsel erfolgreich. Die &Auml;nderungen werden beim laden der nächsten Seite wirksam.'), '', 1);  //FIX meldungen auserhalb/standart?!?
        } else {
            $func->error(t('Dein Benutzerlevel ist geringer, als das des Ziel-Benutzers. Ein Wechsel ist daher untersagt'), '', 1); //FIX meldungen auserhalb/standart?!
        }
    }

    /**
     * Switch back to Adminuser
     * Logout from the selected User and go back to the calling Adminuser
     *
     * @return void
     */
    public function switchback()
    {
        global $db, $func;

        if ($_SESSION['auth']['olduserid'] > 0) {
            // Link session ID to origin user ID
            $db->qry('UPDATE %prefix%stats_auth SET userid=%int%, login=\'1\' WHERE sessid=%string%', $_SESSION['auth']['olduserid'], $this->auth["sessid"]);
            // Delete switch back code in admins user data
            $db->qry('UPDATE %prefix%user SET switch_back = \'\' WHERE userid = %int%', $_SESSION['auth']['olduserid']);
            // Unset switch session data
            $_SESSION['auth']['olduserid'] = '';

            $func->confirmation(t('Benutzerwechsel erfolgreich. Die Änderungen werden beim laden der nächsten Seite wirksam.'), '', 1);
        } else {
            $func->information(t('Fehler: Keine Switchbackdaten gefunden!'), '', 1);
        }
    }

    /**
     * Check user rights and add a error message if needed
     *
     * @param int $requirement
     * @return boolean
     */
    public function authorized($requirement)
    {
        global $func;

        switch ($requirement) {
            // Logged in
            case 1:
                if ($this->auth['login']) {
                    return true;
                } else {
                    $func->information('NO_LOGIN');
                }
                break;

            // Type is Admin, or Superadmin
            case 2:
                if ($this->auth['type'] > 1) {
                    return true;
                } elseif (!$this->auth['login']) {
                    $func->information('NO_LOGIN');
                } else {
                    $func->information('ACCESS_DENIED');
                }
                break;

            // Type is Superadmin
            case 3:
                if ($this->auth['type'] > 2) {
                    return true;
                } elseif (!$this->auth['login']) {
                    $func->information('NO_LOGIN');
                } else {
                    $func->information('ACCESS_DENIED');
                }
                break;

            // Type is User, or less
            case 4:
                if ($this->auth['type'] < 2) {
                    return true;
                } else {
                    $func->information('ACCESS_DENIED');
                }
                break;

            // Logged out
            case 5:
                if (!$this->auth['login']) {
                    return true;
                } else {
                    $func->information('ACCESS_DENIED');
                }
                break;

            default:
                return true;
        }

        return false;
    }

    /**
     * Returns the old Userid if one is set.
     *
     * @return int
     */
    public function get_olduserid()
    {
        return $_SESSION['auth']['olduserid'];
    }

    /**
     * Load all needed Auth-Data from DB and set to auth[]
     *
     * @return mixed
     */
    private function loadAuthBySID()
    {
        global $db;
        // Put all User-Data into $auth-Array
        $user_data = $db->qry_first('SELECT 1 AS found, session.userid, session.login, session.ip, user.*
            FROM %prefix%stats_auth AS session
            LEFT JOIN %prefix%user AS user ON user.userid = session.userid
            WHERE session.sessid=%string% ORDER BY session.lasthit', $this->auth["sessid"]);
        if (is_array($user_data)) {
            foreach ($user_data as $key => $val) {
                if (!is_numeric($key)) {
                    $this->auth[$key] = $val;
                }
            }
        }
        return $this->auth['login'];
    }

    /**
     * Update visit data in stats_auth Table
     *
     * @param string $frmwrkmode
     * @return void
     */
    private function update_visits($frmwrkmode = "")
    {
        global $db;
        if ($frmwrkmode != "ajax" && $frmwrkmode != "print" && $frmwrkmode != "popup" && $frmwrkmode != "base") {
            // Update visits, hits, IP and lasthit
            $visit_timeout = time() - 60*60;
            // If a session loaded no page for over one hour, this counts as a new visit
            $db->qry('UPDATE %prefix%stats_auth SET visits = visits + 1 WHERE (sessid=%string%) AND (lasthit < %int%)', $this->auth["sessid"], $visit_timeout);
            // Update user-stats and lasthit, so the timeout is resetted
            $db->qry('UPDATE %prefix%stats_auth SET lasthit=%int%, hits = hits + 1, ip=%string%, lasthiturl= %string% WHERE sessid=%string%', $this->timestamp, $this->auth["ip"], $_SERVER['REQUEST_URI'], $this->auth["sessid"]);
        }

        // Heartbeat
        if ($frmwrkmode == "ajax") {
            $db->qry('UPDATE %prefix%stats_auth SET lastajaxhit=%int% WHERE sessid=%string%', $this->timestamp, $this->auth["sessid"]);
        }
    }

    private function regenerateSessionId()
    {
        session_regenerate_id();
        $this->auth["sessid"] = session_id();
    }
}
