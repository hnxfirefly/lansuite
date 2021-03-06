<?php

class db
{
    public $link_id = 0;
    public $query_id = 0;
    public $record = array();
    public $success = false;
    public $count_query = 0;
    public $errors = '';
    public $errorsFound = 0;
    public $connectfailure = 0;  //0= no error, 1=connection error, 2=database error
    public $QueryArgs = array();

    // Internal only
    public function print_error($msg, $query_string_with_error)
    {
        global $config, $auth;

        $error = t('SQL-Failure. Database respondet: <b>%1</b><br /><br />Query: <br /><i>%2</i>', $msg, $query_string_with_error);

        $this->errors .= $error . '<br />';
        $this->errorsFound = 1;

        // Need to use mysql_querys here, to prevent loops!!
        $query = 'INSERT INTO '. $config['database']['prefix'] .'log SET date = NOW(), userid = '. (int)$auth['userid'] .', type = 3, description = "'. strip_tags($error) .'", sort_tag = "SQL-Fehler"';
        mysqli_query($this->link_id, $query);
        $this->count_query++;
    }

    public function escape($match)
    {
        $CurrentArg = array_shift($this->QueryArgs);

        if ($match[0] == '%int%') {
            return (int)$CurrentArg;

        } elseif ($match[0] == '%string%') {
            $CurrentArg = stripslashes($CurrentArg);
            return "'". mysqli_real_escape_string($this->link_id, (string)$CurrentArg) ."'";

        } elseif ($match[0] == '%plain%') {
            return $CurrentArg;
        }
    }

    #### Connection related ####

    public function connect($save = false)
    {
        global $config;

        $server = $config['database']['server'];
        $user = $config['database']['user'];
        $pass = $config['database']['passwd'];
        $database = $config['database']['database'];
        $charset = $config['database']['charset'];

        // Try to connect
        $this->link_id = mysqli_connect($server, $user, $pass);

        if (!$this->link_id) {
            if ($save) {
                $this->connectfailure = 1;
                $this->success = false;
                return false;
            } else {
                echo HTML_FONT_ERROR . t('Die Verbindung zur Datenbank ist fehlgeschlagen. Lansuite wird abgebrochen') . HTML_FONT_END;
                exit();
            }

        // Try to select DB
        } else {
            $ret = mysqli_select_db($this->link_id, $database);
            if (!$ret) {
                if ($save) {
                    $this->connectfailure = 2;
                    $this->success = false;
                    return false;
                } else {
                    echo HTML_FONT_ERROR . t("Die Datenbank '%1' konnte nicht ausgewählt werden. Lansuite wird abgebrochen", $database) . HTML_FONT_END;
                    exit();
                }
            }
        }

        // Set encoding based on config file
        if (!empty($charset)) {
              $this->link_id->set_charset($charset);
        } else {
            $this->link_id->set_charset('utf8');
        }
        $this->success = true;
        $this->connectfailure = 0;
        return true;
    }

    public function set_charset()
    {
        mysqli_query($this->link_id, "/*!40101 SET NAMES utf8_general_ci */;");
    }

    public function get_host_info()
    {
        return mysqli_get_host_info($this->link_id);
    }

    public function disconnect()
    {
        mysqli_close($this->link_id);
    }


    #### Queries ####

    /**
     * If the second parameter is an array, the function uses the array as value list.
     *
     * @return bool|int|mysqli_result
     */
    public function qry()
    {
        global $config, $debug;

        // Arguments could be passed als multiple ones, or a single array
        $this->QueryArgs = func_get_args();
        if (is_array($this->QueryArgs[0])) {
            $this->QueryArgs = $this->QueryArgs[0];
        }

        $query = array_shift($this->QueryArgs);

        $query = str_replace('%prefix%', $config['database']['prefix'], $query);
        $query = preg_replace_callback('#(%string%|%int%|%plain%)#sUi', array(&$this, 'escape'), $query);

        // TODO: Don't replace %prefix% within quotes!
        if (isset($debug)) {
            $debug->query_start($query);
        }

        $this->query_id = mysqli_query($this->link_id, $query);
        $this->sql_error = mysqli_error($this->link_id);

        if (!$this->query_id) {
            $this->print_error($this->sql_error, $query);
        }

        $this->count_query++;
        if (isset($debug)) {
            $debug->query_stop($this->sql_error);
        }
        $this->QueryArgs = array();

        return $this->query_id;
    }

    public function fetch_array($query_id = -1, $save = 1)
    {
        global $func;

        if ($query_id != -1) {
            $this->query_id = $query_id;
        }

        $this->record = mysqli_fetch_array($this->query_id);

        if ($save and $this->record) {
            foreach ($this->record as $key => $value) {
                $this->record[$key] = $func->NoHTML($value);
            }
        }

        return $this->record;
    }

    public function num_rows($query_id = -1)
    {
        if ($query_id != -1) {
            $this->query_id = $query_id;
        }

        return mysqli_num_rows($this->query_id);
    }

    public function get_affected_rows($query_id = -1)
    {
        if ($query_id != -1) {
            $this->query_id = $query_id;
        }

        return mysqli_affected_rows($this->link_id);
    }

    public function insert_id($query_id = -1)
    {
        if ($query_id != -1) {
            $this->query_id = $query_id;
        }

        return mysqli_insert_id($this->link_id);
    }

    public function num_fields($query_id = -1)
    {
        if ($query_id != -1) {
            $this->query_id = $query_id;
        }

        return mysqli_num_fields($this->query_id);
    }

    public function field_name($pos, $query_id = -1)
    {
        if ($query_id != -1) {
            $this->query_id = $query_id;
        }

        $finfo = mysqli_fetch_field_direct($this->query_id, $pos);
        return $finfo->name;
    }

    public function free_result($query_id = -1)
    {
        if ($query_id != -1) {
            $this->query_id = $query_id;
        }

        return mysqli_free_result($this->query_id);
    }

    #### Special ####

    /**
     * If the second parameter is an array, the function uses the array as value list.
     *
     * @return array|bool|null
     */
    public function qry_first()
    {
        $this->qry($args = func_get_args());

        // For execute querys $this->query_id will not be a resource that needs to be freed.
        if ($this->query_id === true) {
            return true;
        }

        $row = $this->fetch_array();
        $this->free_result();
        return $row;
    }

    public function qry_first_rows()
    {
        $this->qry($args = func_get_args());
        $row = $this->fetch_array();
        $row['number'] = $this->num_rows(); // fieldname "number" is reserved
        $this->free_result();
        return $row;
    }

    #### Misc ####

    public function client_info()
    {
        return mysqli_get_client_info();
    }

    public function DisplayErrors()
    {
        global $cfg, $func;

        if ($cfg['show_mysql_errors'] and $this->errors) {
            $func->error($this->errors);
            $this->errors = '';
        }
    }
}