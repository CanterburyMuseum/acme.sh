#!/usr/bin/env sh
# shellcheck disable=SC2034
dns_myhost_info='myhost-clients.com
Site: myhost-clients.com
Docs: github.com/acmesh-official/acme.sh/wiki/dnsapi#dns_myhost
Options:
 MYHOST_Username Username
 MYHOST_Password Password
 MYHOST_TOTP_SECRET TOTP Secret (Optional)
'

# Usage: dns_myhost_add _acme-challenge.subdomain.domain.com "XKrxpRBosdIKFzxW_CT3KLZNf6q0HG9i01zxXp5CPBs"
dns_myhost_add() {
  fulldomain=$1
  txtvalue=$2

  _info "Using myhost-clients.com to add TXT record"
  _myhost_process "add" "$fulldomain" "$txtvalue"
}

# Usage: dns_myhost_rm _acme-challenge.subdomain.domain.com "XKrxpRBosdIKFzxW_CT3KLZNf6q0HG9i01zxXp5CPBs"
dns_myhost_rm() {
  fulldomain=$1
  txtvalue=$2

  _info "Using myhost-clients.com to remove TXT record"
  _myhost_process "rm" "$fulldomain" "$txtvalue"
}

####################  Private functions below ##################################

_myhost_totp() {
  _secret="$1"
  # 1. Clean the secret and convert to uppercase
  _secret=$(echo "$_secret" | tr -d ' \n\r' | tr 'abcdefghijklmnopqrstuvwxyz' 'ABCDEFGHIJKLMNOPQRSTUVWXYZ')

  # 2. Pure POSIX Base32 to Hexadecimal conversion
  _hex_secret=""
  _b32_chars="ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
  
  # Process Base32 string character by character
  _buffer=0
  _bits_in_buffer=0
  _rest="$_secret"
  while [ -n "$_rest" ]; do
    _char="${_rest%${_rest#?}}"
    _rest="${_rest#?}"
    [ "$_char" = "=" ] && break # Ignore padding
    
    # Find index of char in B32 alphabet
    _prefix="${_b32_chars%%$_char*}"
    _val=${#_prefix}
    [ $_val -eq 32 ] && continue

    _buffer=$(($_buffer << 5 | _val))
    _bits_in_buffer=$(($_bits_in_buffer + 5))

    while [ $_bits_in_buffer -ge 8 ]; do
      _bits_in_buffer=$(($_bits_in_buffer - 8))
      _byte=$(($_buffer >> _bits_in_buffer & 255))
      _hex_byte=$(printf "%02x" $_byte)
      _hex_secret="${_hex_secret}${_hex_byte}"
      _buffer=$(($_buffer & $(( (1 << _bits_in_buffer) - 1 )) ))
    done
  done

  # 3. Get current 30-second time step in Hex (padded to 16 chars / 8 bytes)
  _time_step=$(($(date +%s) / 30))
  _hex_time=$(printf "%016x" $_time_step)

  # 4. Generate HMAC-SHA1 using OpenSSL (Output format: hex string)
  _hmac=$(printf "%s" "$_hex_time" | _h2b | openssl dgst -sha1 -mac HMAC -macopt "hexkey:$_hex_secret" | sed 's/^.*= //')

  # 5. Dynamic Truncation (Extract 4 bytes based on the last nibble offset)
  _last_char="${_hmac#${_hmac%?}}"
  _offset=$((0x$_last_char * 2))
  _part_hex=$(printf "%s" "$_hmac" | cut -c $((_offset + 1))-$((_offset + 8)))
  
  # Mask the most significant bit to avoid signed integer issues
  _num=$((0x$_part_hex & 0x7fffffff))

  # 6. Generate 6-digit PIN
  _pin=$(($_num % 1000000))
  printf "%06d" $_pin
}

_myhost_check_config() {
  MYHOST_Username="${MYHOST_Username:-$(_readaccountconf_mutable MYHOST_Username)}"
  MYHOST_Username="${MYHOST_Username:-$MYHOST_USERNAME}"
  MYHOST_Username="${MYHOST_Username:-$(_readaccountconf_mutable MYHOST_USERNAME)}"

  MYHOST_Password="${MYHOST_Password:-$(_readaccountconf_mutable MYHOST_Password)}"
  MYHOST_Password="${MYHOST_Password:-$MYHOST_PASSWORD}"
  MYHOST_Password="${MYHOST_Password:-$(_readaccountconf_mutable MYHOST_PASSWORD)}"

  MYHOST_TOTP_SECRET="${MYHOST_TOTP_SECRET:-$(_readaccountconf_mutable MYHOST_TOTP_SECRET)}"

  if [ -z "$MYHOST_Username" ] || [ -z "$MYHOST_Password" ]; then
    _err "You didn't specify myhost-clients.com username and password yet."
    _err "Usage: export MYHOST_Username=<name>"
    _err "Usage: export MYHOST_Password=<password>"
    return 1
  fi

  _saveaccountconf_mutable MYHOST_Username "$MYHOST_Username"
  _saveaccountconf_mutable MYHOST_Password "$MYHOST_Password"
  if [ -n "$MYHOST_TOTP_SECRET" ]; then
    _saveaccountconf_mutable MYHOST_TOTP_SECRET "$MYHOST_TOTP_SECRET"
  fi
  return 0
}

_myhost_init_http() {
  if type _inithttp >/dev/null 2>&1; then
    _inithttp
  fi
  if [ -n "$_ACME_CURL" ] && ! _contains "$_ACME_CURL" "--cookie-jar"; then
    _ACME_CURL="$_ACME_CURL --cookie $_COOKIE_JAR --cookie-jar $_COOKIE_JAR "
  fi
  if [ -n "$_ACME_WGET" ] && ! _contains "$_ACME_WGET" "--save-cookies"; then
    _ACME_WGET="$_ACME_WGET --load-cookies=$_COOKIE_JAR --save-cookies=$_COOKIE_JAR --keep-session-cookies "
  fi
}

_myhost_login() {
  _info "Logging in to myhost-clients.com..."

  # Reset headers for the first get
  _resethttp
  _myhost_init_http

  _login_page=$(_get "https://myhost-clients.com/login")

  # Extract CSRF token
  _token=$(echo "$_login_page" | grep 'name="token"' | _egrep_o 'value="[^"]*"' | cut -d '"' -f 2 | _head_n 1)
  if [ -z "$_token" ]; then
    _token=$(echo "$_login_page" | sed -n 's/.*name="token" value="\([^"]*\)".*/\1/p' | _head_n 1)
  fi

  if [ -z "$_token" ]; then
    _err "Cannot find CSRF token on login page."
    return 1
  fi
  _debug "Login CSRF token: $_token"

  # POST login credentials
  _enc_user=$(printf "%s" "$MYHOST_Username" | _url_encode)
  _enc_pass=$(printf "%s" "$MYHOST_Password" | _url_encode)
  _enc_token=$(printf "%s" "$_token" | _url_encode)

  _post_body="username=${_enc_user}&password=${_enc_pass}&rememberme=on&token=${_enc_token}"

  _login_response=$(_post "$_post_body" "https://myhost-clients.com/login")

  # Check if 2fa challenge
  _redirect_to_2fa=0
  if [ -f "$HTTP_HEADER" ] && grep -i -q "location:.*/login/challenge" "$HTTP_HEADER"; then
    _redirect_to_2fa=1
  fi

  if _contains "$_login_response" "/login/challenge/verify" || [ "$_redirect_to_2fa" -eq 1 ]; then
    _info "Two-factor authentication challenge detected."
    if [ -z "$MYHOST_TOTP_SECRET" ]; then
      _err "Two-factor authentication is required, but MYHOST_TOTP_SECRET is not set."
      return 1
    fi

    # If the response doesn't contain the form, fetch the challenge page directly
    if ! _contains "$_login_response" "/login/challenge/verify"; then
      _login_response=$(_get "https://myhost-clients.com/login/challenge")
    fi

    # Extract CSRF token for the 2fa post form
    _token=$(echo "$_login_response" | grep 'name="token"' | _egrep_o 'value="[^"]*"' | cut -d '"' -f 2 | _head_n 1)
    if [ -z "$_token" ]; then
      _token=$(echo "$_login_response" | sed -n 's/.*name="token" value="\([^"]*\)".*/\1/p' | _head_n 1)
    fi

    if [ -z "$_token" ]; then
      _err "Cannot find CSRF token on 2fa page."
      return 1
    fi
    _debug "2fa CSRF token: $_token"

    _pin=$(_myhost_totp "$MYHOST_TOTP_SECRET")
    _debug "Generated TOTP pin: $_pin"

    _enc_token=$(printf "%s" "$_token" | _url_encode)
    _enc_pin=$(printf "%s" "$_pin" | _url_encode)
    _post_body="token=${_enc_token}&key=${_enc_pin}"

    _login_response=$(_post "$_post_body" "https://myhost-clients.com/login/challenge/verify")

    if _contains "$_login_response" "/login/challenge/verify" || (_contains "$_login_response" "username" && _contains "$_login_response" "password"); then
      _err "Two-factor authentication failed."
      return 1
    fi
  elif _contains "$_login_response" "username" && _contains "$_login_response" "password"; then
    _err "Login failed. Please check your username and password."
    return 1
  fi

  _info "Successfully logged in."
  return 0
}

_myhost_get_domain_id() {
  _doms_html="$1"
  _search_domain="$2"
  _flat_html=$(echo "$_doms_html" | tr '\n\r\t' ' ' | tr -s ' ')

  _escaped_domain=$(echo "$_search_domain" | sed 's/\./\\./g')

  # Search for checkbox domids[] and domain name link
  _dom_id=$(echo "$_flat_html" | sed -n 's/.*name="domids\[\]" class="domids stopEventBubble" value="\([0-9]*\)" \?\/>\s*<\/td>\s*<td[^>]*>\s*<a href="https\?:\/\/'"$_escaped_domain"'".*/\1/p')

  if [ -z "$_dom_id" ]; then
    _dom_id=$(echo "$_flat_html" | sed -n 's/.*value="\([0-9]*\)"[^>]*>\s*<\/td>\s*<td[^>]*>\s*<a href="https\?:\/\/'"$_escaped_domain"'".*/\1/p')
  fi

  echo "$_dom_id"
}

_myhost_parse_records() {
  _html="$1"
  echo "$_html" | tr -d '\n\r' | sed 's/<\/tr>/<\/tr>\n/g' | awk -v sq="'" '
    function get_input_val(line, name,    val, m, n, tags, i, j, opt_tag, tag, sq_regex) {
      n = split(line, tags, "<")
      sq_regex = "value=" sq "[^" sq "]*" sq
      for (i = 1; i <= n; i++) {
        tag = tags[i]
        if (index(tag, "name=\"" name "\"") > 0 || index(tag, "name=" sq name sq) > 0) {
          if (substr(tag, 1, 6) == "select") {
            for (j = i + 1; j <= n; j++) {
              opt_tag = tags[j]
              if (substr(opt_tag, 1, 7) == "/select") break
              if (index(opt_tag, "selected") > 0) {
                if (match(opt_tag, /value="[^"]*"/)) {
                  return substr(opt_tag, RSTART+7, RLENGTH-8)
                } else if (match(opt_tag, sq_regex)) {
                  return substr(opt_tag, RSTART+7, RLENGTH-8)
                }
              }
            }
          } else {
            if (match(tag, /value="[^"]*"/)) {
              return substr(tag, RSTART+7, RLENGTH-8)
            } else if (match(tag, sq_regex)) {
              return substr(tag, RSTART+7, RLENGTH-8)
            }
          }
          return ""
        }
      }
      return ""
    }
    
    (index($0, "name=\"name[]\"") > 0 || index($0, "name=" sq "name[]" sq) > 0) {
      print "name:" get_input_val($0, "name[]")
      print "ttl:" get_input_val($0, "ttl[]")
      print "type:" get_input_val($0, "type[]")
      print "value:" get_input_val($0, "value[]")
      print "priority:" get_input_val($0, "priority[]")
      print "port:" get_input_val($0, "port[]")
      print "weight:" get_input_val($0, "weight[]")
      print "flag:" get_input_val($0, "flag[]")
      print "tag:" get_input_val($0, "tag[]")
      print "line:" get_input_val($0, "line[]")
      print ""
    }
  '
}

_myhost_process() {
  _action="$1"
  fulldomain="$2"
  txtvalue="$3"

  if ! _myhost_check_config; then
    return 1
  fi

  # Initialize Cookie Jar
  _COOKIE_JAR=""
  if [ -n "$LE_CONFIG_HOME" ]; then
    _COOKIE_JAR="$LE_CONFIG_HOME/myhost_cookie.jar"
  else
    _COOKIE_JAR="$(_mktemp)"
  fi
  touch "$_COOKIE_JAR"

  if ! _myhost_login; then
    rm -f "$_COOKIE_JAR"
    return 1
  fi

  # Fetch domains page and get domain_id
  _info "Fetching domains list..."
  _domains_page=$(_get "https://myhost-clients.com/clientarea.php?action=domains")

  _sub_domain=""
  _domain=""
  _domain_id=""

  _i=1
  while true; do
    _attempted_zone=$(echo "$fulldomain" | cut -d . -f "$_i"-100)
    if [ -z "$_attempted_zone" ] || ! _contains "$_attempted_zone" "\\."; then
      break
    fi
    _debug "Checking zone candidate: $_attempted_zone"
    _dom_id=$(_myhost_get_domain_id "$_domains_page" "$_attempted_zone")
    if [ -n "$_dom_id" ]; then
      _domain_id="$_dom_id"
      _domain="$_attempted_zone"
      if [ "$_i" -eq 1 ]; then
        _sub_domain=""
      else
        _prev=$(_math "$_i" - 1)
        _sub_domain=$(echo "$fulldomain" | cut -d . -f 1-"$_prev")
      fi
      break
    fi
    _i=$(_math "$_i" + 1)
  done

  if [ -z "$_domain_id" ]; then
    _err "Domain not found in myhost-clients.com account: $fulldomain"
    rm -f "$_COOKIE_JAR"
    return 1
  fi
  _debug "Found domain_id: $_domain_id"
  _debug "Root zone: $_domain"
  _debug "Subdomain: $_sub_domain"

  # Fetch records page
  _info "Fetching DNS records..."
  _dnsmanager_page=$(_get "https://myhost-clients.com/index.php?m=br_dnsmanager&id=${_domain_id}")

  # Extract CSRF token
  _token=$(echo "$_dnsmanager_page" | grep 'name="token"' | _egrep_o 'value="[^"]*"' | cut -d '"' -f 2 | _head_n 1)
  if [ -z "$_token" ]; then
    _token=$(echo "$_dnsmanager_page" | sed -n 's/.*name="token" value="\([^"]*\)".*/\1/p' | _head_n 1)
  fi

  if [ -z "$_token" ]; then
    _err "Cannot find CSRF token on DNS manager page."
    rm -f "$_COOKIE_JAR"
    return 1
  fi
  _debug "Found CSRF token: $_token"

  _new_record_exists=0
  _record_modified=0

  # Build post body starting with token
  _post_body="token=$(printf "%s" "$_token" | _url_encode)"

  _r_name=""
  _r_ttl=""
  _r_type=""
  _r_value=""
  _r_priority=""
  _r_port=""
  _r_weight=""
  _r_flag=""
  _r_tag=""
  _r_line=""

  while read -r _line; do
    if [ -z "$_line" ]; then
      # End of record. Check if we need to process/add/skip this record.
      if [ -z "$_r_name" ] && [ -z "$_r_value" ]; then
        # Reset and continue
        _r_name=""; _r_ttl=""; _r_type=""; _r_value=""; _r_priority=""; _r_port=""; _r_weight=""; _r_flag=""; _r_tag=""; _r_line=""
        continue
      fi

      if [ "$_action" = "add" ]; then
        if [ "$_r_name" = "$_sub_domain" ] && [ "$_r_type" = "TXT" ] && [ "$_r_value" = "$txtvalue" ]; then
          _new_record_exists=1
        fi
      elif [ "$_action" = "rm" ]; then
        if [ "$_r_name" = "$_sub_domain" ] && [ "$_r_type" = "TXT" ] && [ "$_r_value" = "$txtvalue" ]; then
          _debug "Removing record: $_r_name $_r_type $_r_value"
          _record_modified=1
          # Reset and continue (do not append to _post_body)
          _r_name=""; _r_ttl=""; _r_type=""; _r_value=""; _r_priority=""; _r_port=""; _r_weight=""; _r_flag=""; _r_tag=""; _r_line=""
          continue
        fi
      fi

      _enc_name=$(printf "%s" "$_r_name" | _url_encode)
      _enc_ttl=$(printf "%s" "$_r_ttl" | _url_encode)
      _enc_type=$(printf "%s" "$_r_type" | _url_encode)
      _enc_value=$(printf "%s" "$_r_value" | _url_encode)
      _enc_priority=$(printf "%s" "$_r_priority" | _url_encode)
      _enc_port=$(printf "%s" "$_r_port" | _url_encode)
      _enc_weight=$(printf "%s" "$_r_weight" | _url_encode)
      _enc_flag=$(printf "%s" "$_r_flag" | _url_encode)
      _enc_tag=$(printf "%s" "$_r_tag" | _url_encode)
      _enc_line=$(printf "%s" "$_r_line" | _url_encode)

      _post_body="${_post_body}&name%5B%5D=${_enc_name}&ttl%5B%5D=${_enc_ttl}&type%5B%5D=${_enc_type}&value%5B%5D=${_enc_value}&priority%5B%5D=${_enc_priority}&port%5B%5D=${_enc_port}&weight%5B%5D=${_enc_weight}&flag%5B%5D=${_enc_flag}&tag%5B%5D=${_enc_tag}&line%5B%5D=${_enc_line}"

      # Reset for next record
      _r_name=""; _r_ttl=""; _r_type=""; _r_value=""; _r_priority=""; _r_port=""; _r_weight=""; _r_flag=""; _r_tag=""; _r_line=""
      continue
    fi

    # Parse key:value
    _key="${_line%%:*}"
    _val="${_line#*:}"

    case "$_key" in
      name) _r_name="$_val" ;;
      ttl) _r_ttl="$_val" ;;
      type) _r_type="$_val" ;;
      value) _r_value="$_val" ;;
      priority) _r_priority="$_val" ;;
      port) _r_port="$_val" ;;
      weight) _r_weight="$_val" ;;
      flag) _r_flag="$_val" ;;
      tag) _r_tag="$_val" ;;
      line) _r_line="$_val" ;;
    esac
  done <<EOF
$(_myhost_parse_records "$_dnsmanager_page")
EOF

  # Process any remaining record after loop exits (in case command substitution stripped trailing newlines)
  if [ -n "$_r_name" ] || [ -n "$_r_value" ]; then
    if [ "$_action" = "add" ]; then
      if [ "$_r_name" = "$_sub_domain" ] && [ "$_r_type" = "TXT" ] && [ "$_r_value" = "$txtvalue" ]; then
        _new_record_exists=1
      fi
    elif [ "$_action" = "rm" ]; then
      if [ "$_r_name" = "$_sub_domain" ] && [ "$_r_type" = "TXT" ] && [ "$_r_value" = "$txtvalue" ]; then
        _debug "Removing record: $_r_name $_r_type $_r_value"
        _record_modified=1
        _r_name=""
      fi
    fi

    if [ -n "$_r_name" ]; then
      _enc_name=$(printf "%s" "$_r_name" | _url_encode)
      _enc_ttl=$(printf "%s" "$_r_ttl" | _url_encode)
      _enc_type=$(printf "%s" "$_r_type" | _url_encode)
      _enc_value=$(printf "%s" "$_r_value" | _url_encode)
      _enc_priority=$(printf "%s" "$_r_priority" | _url_encode)
      _enc_port=$(printf "%s" "$_r_port" | _url_encode)
      _enc_weight=$(printf "%s" "$_r_weight" | _url_encode)
      _enc_flag=$(printf "%s" "$_r_flag" | _url_encode)
      _enc_tag=$(printf "%s" "$_r_tag" | _url_encode)
      _enc_line=$(printf "%s" "$_r_line" | _url_encode)

      _post_body="${_post_body}&name%5B%5D=${_enc_name}&ttl%5B%5D=${_enc_ttl}&type%5B%5D=${_enc_type}&value%5B%5D=${_enc_value}&priority%5B%5D=${_enc_priority}&port%5B%5D=${_enc_port}&weight%5B%5D=${_enc_weight}&flag%5B%5D=${_enc_flag}&tag%5B%5D=${_enc_tag}&line%5B%5D=${_enc_line}"
    fi
  fi

  if [ "$_action" = "add" ]; then
    if [ "$_new_record_exists" -eq 1 ]; then
      _info "Record already exists, no need to add."
      rm -f "$_COOKIE_JAR"
      return 0
    fi

    _enc_name=$(printf "%s" "$_sub_domain" | _url_encode)
    _enc_ttl=$(printf "%s" "300" | _url_encode)
    _enc_type=$(printf "%s" "TXT" | _url_encode)
    _enc_value=$(printf "%s" "$txtvalue" | _url_encode)

    _post_body="${_post_body}&add_name%5B%5D=${_enc_name}&add_ttl%5B%5D=${_enc_ttl}&add_type%5B%5D=${_enc_type}&add_value%5B%5D=${_enc_value}&add_priority%5B%5D=&add_port%5B%5D=&add_weight%5B%5D=&add_flag%5B%5D=&add_tag%5B%5D="
    _record_modified=1
  else
    _post_body="${_post_body}&add_name%5B%5D=&add_ttl%5B%5D=&add_type%5B%5D=&add_value%5B%5D=&add_priority%5B%5D=&add_port%5B%5D=&add_weight%5B%5D=&add_flag%5B%5D=&add_tag%5B%5D="
  fi

  if [ "$_action" = "rm" ] && [ "$_record_modified" -eq 0 ]; then
    _info "Record not found, no need to remove."
    rm -f "$_COOKIE_JAR"
    return 0
  fi

  _post_body="${_post_body}&__codename__=busyrack"

  _info "Updating DNS records..."
  _dnsmanager_response=$(_post "$_post_body" "https://myhost-clients.com/index.php?m=br_dnsmanager&id=${_domain_id}")

  if [ "$?" -ne 0 ]; then
    _err "Failed to post update to DNS manager."
    rm -f "$_COOKIE_JAR"
    return 1
  fi

  rm -f "$_COOKIE_JAR"
  _info "TXT record processed successfully."
  return 0
}
