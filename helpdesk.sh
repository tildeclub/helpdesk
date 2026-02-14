#!/usr/bin/env bash
# shellcheck disable=SC2086,SC2155

DB_PATH="/home/help/helpdesk.db"

SQLITE_BIN="/usr/bin/sqlite3"
SMTP_BIN="${SMTP_BIN:-/home/help/.local/bin/msmtp}"

CHPASSWD_BIN="/usr/sbin/chpasswd"
BASH_BIN="/usr/bin/bash"
USERMOD_BIN="/usr/sbin/usermod"
GROUPMOD_BIN="/usr/sbin/groupmod"
LOGINCTL_BIN="$(command -v loginctl || true)"
PKILL_BIN="$(command -v pkill || true)"
KILLALL_BIN="$(command -v killall || true)"
PGREP_BIN="$(command -v pgrep || true)"
CRONTAB_BIN="$(command -v crontab || true)"
GETENT_BIN="/usr/bin/getent"
TIMEOUT_BIN="$(command -v timeout || true)"

GREP_BIN="/usr/bin/grep"
SED_BIN="/usr/bin/sed"
TR_BIN="/usr/bin/tr"
XARGS_BIN="$(command -v xargs || true)"
MKTEMP_BIN="$(command -v mktemp || true)"
STAT_BIN="$(command -v stat || true)"

HELP_FROM_ADDR="root@tilde.club"
HELP_FROM_NAME="tilde.club Help Desk"
SEND_TIMEOUT="${SEND_TIMEOUT:-30s}"

BAD_USERNAMES_FILE="/etc/tildeclub/bad_usernames.txt"
BAD_USERNAMES=(
  "0x0" abuse admin administrator auth autoconfig bbj broadcasthost cloud
  daemon bin sys sync shutdown halt games
  docker podman kube kubernetes elastic grafana prometheus
  elastic grafana prometheus forum ftp git gopher help hostmaster imap info irc
  is isatap it localdomain localhost lounge mail "mailer-daemon" mailnull marketing marketting
  mis news nobody noc noreply mysql mariadb postgres postgresadmin oracle mongodb
  redis rabbitmq operator pop pop3 postfix postmaster
  rabbitmq retro root sales security smtp ssladmin ssladministrator sslwebmaster
  staff superuser support sys sysadmin team temp test testing uucp user users
  usenet web webadmin webmaster wpad www znc openpgpkey guest
)

warn_if_insecure_perms() {
  local path="$1" label="$2"
  [[ -n "$path" && -e "$path" && -n "$STAT_BIN" ]] || return 0
  local mode owner group
  mode="$("$STAT_BIN" -c '%a' "$path" 2>/dev/null || true)"
  owner="$("$STAT_BIN" -c '%U' "$path" 2>/dev/null || true)"
  group="$("$STAT_BIN" -c '%G' "$path" 2>/dev/null || true)"
  if [[ -n "$mode" ]]; then
    if (( (10#$mode % 100) != 0 )); then
      echo "Warning: $label ($path) permissions look open ($mode, owner=$owner group=$group). Consider chmod 600." >&2
    fi
  fi
}

warn_if_insecure_perms "$DB_PATH" "helpdesk database"
warn_if_insecure_perms "$HOME/.env" ".env credentials file"

db_scalar() {
  local sql="$1"
  "$SQLITE_BIN" -batch -noheader "$DB_PATH" <<<"$sql" 2>/dev/null || true
}

db_exec() {
  local sql="$1"
  "$SQLITE_BIN" -batch "$DB_PATH" <<<"$sql" >/dev/null 2>&1 || true
}

load_smtp_env() {
  local env_file="$HOME/.env"
  [[ -f "$env_file" ]] || return 0

  local k v
  while IFS='=' read -r k v; do
    [[ -n "$k" ]] || continue

    v="${v%$'\r'}"

    if [[ "$v" =~ ^\".*\"$ ]]; then
      v="${v#\"}"; v="${v%\"}"
    elif [[ "$v" =~ ^\'.*\'$ ]]; then
      v="${v#\'}"; v="${v%\'}"
    fi

    case "$k" in
      SMTP_SERVER) SMTP_SERVER="$v" ;;
      SMTP_PORT) SMTP_PORT="$v" ;;
      SMTP_USER) SMTP_USER="$v" ;;
      SMTP_PASS) SMTP_PASS="$v" ;;
      SMTP_TLS) SMTP_TLS="$v" ;;
      SMTP_CA_FILE) SMTP_CA_FILE="$v" ;;
      SMTP_TLS_CERTCHECK) SMTP_TLS_CERTCHECK="$v" ;;
    esac
  done < <("$GREP_BIN" -E '^(SMTP_SERVER|SMTP_PORT|SMTP_USER|SMTP_PASS|SMTP_TLS|SMTP_CA_FILE|SMTP_TLS_CERTCHECK)=' "$env_file" 2>/dev/null || true)

  return 0
}

generate_code() { /usr/bin/openssl rand -base64 32; }

sql_escape() { printf '%s' "$1" | "$SED_BIN" "s/'/''/g"; }

send_email() {
  local to="$1" subject="$2" body="$3"
  local mid="<$(date +%s).$(/usr/bin/openssl rand -hex 8)@tilde.club>"

  to="${to//$'\r'/}"; to="${to//$'\n'/}"
  subject="${subject//$'\r'/}"; subject="${subject//$'\n'/}"

  [[ -x "$SMTP_BIN" ]] || { echo "Error: msmtp not found." >&2; exit 1; }

  load_smtp_env

  [[ -n "${SMTP_SERVER:-}" ]] || { echo "Error: SMTP_SERVER not set in ~/.env." >&2; exit 1; }
  [[ -n "${SMTP_USER:-}" ]]   || { echo "Error: SMTP_USER not set in ~/.env." >&2; exit 1; }
  [[ -n "${SMTP_PASS:-}" ]]   || { echo "Error: SMTP_PASS not set in ~/.env." >&2; exit 1; }

  local supports_read_recipients=0
  if "$SMTP_BIN" --help 2>&1 | "$GREP_BIN" -q -- '--read-recipients'; then
    supports_read_recipients=1
  fi

  [[ -n "$MKTEMP_BIN" ]] || { echo "Error: mktemp not found." >&2; exit 1; }
  local tmpdir pwfile
  tmpdir="${XDG_RUNTIME_DIR:-/tmp}"
  umask 077
  pwfile="$("$MKTEMP_BIN" -p "$tmpdir" msmtp-pass.XXXXXX 2>/dev/null)" || { echo "Error: unable to create temp file." >&2; exit 1; }
  printf '%s' "$SMTP_PASS" > "$pwfile" 2>/dev/null || { rm -f "$pwfile"; echo "Error: unable to write temp password file." >&2; exit 1; }

  local msmtp_args=(
    --host="$SMTP_SERVER"
    --port="${SMTP_PORT:-587}"
    --tls=$( [[ "${SMTP_TLS:-on}" == "off" ]] && echo off || echo on )
    --auth=on
    --user="$SMTP_USER"
    "--passwordeval=cat $pwfile"
    --from="$HELP_FROM_ADDR"
  )
  [[ "${SMTP_TLS_CERTCHECK:-on}" == "off" ]] && msmtp_args+=(--tls-certcheck=off)
  [[ -n "${SMTP_CA_FILE:-}" ]] && msmtp_args+=(--tls-trust-file="$SMTP_CA_FILE")

  if [[ $supports_read_recipients -eq 1 ]]; then
    msmtp_args+=(--read-recipients)
  else
    echo "Warning: msmtp is too old to support --read-recipients; recipient will be passed in argv (PII leak risk)." >&2
  fi

  local rc=0
  {
    printf 'Date: %s\n' "$(LC_ALL=C date -R)"
    printf 'From: %s <%s>\n' "$HELP_FROM_NAME" "$HELP_FROM_ADDR"
    printf 'To: %s\n' "$to"
    printf 'Subject: %s\n' "$subject"
    printf 'Message-ID: %s\n' "$mid"
    printf 'MIME-Version: 1.0\nContent-Type: text/plain; charset=UTF-8\n\n'
    printf '%b\n' "$body"
  } | {
      if [[ -n "$TIMEOUT_BIN" ]]; then
        if [[ $supports_read_recipients -eq 1 ]]; then
          "$TIMEOUT_BIN" --preserve-status "$SEND_TIMEOUT" "$SMTP_BIN" "${msmtp_args[@]}"
        else
          "$TIMEOUT_BIN" --preserve-status "$SEND_TIMEOUT" "$SMTP_BIN" "${msmtp_args[@]}" -- "$to"
        fi
      else
        if [[ $supports_read_recipients -eq 1 ]]; then
          "$SMTP_BIN" "${msmtp_args[@]}"
        else
          "$SMTP_BIN" "${msmtp_args[@]}" -- "$to"
        fi
      fi
  }
  rc=$?

  rm -f "$pwfile" >/dev/null 2>&1 || true

  unset SMTP_PASS

  [[ $rc -eq 0 ]] || { echo "Error: unable to send email (msmtp failed)." >&2; exit 1; }
}

user_exists() { $GETENT_BIN passwd "$1" >/dev/null 2>&1; }
group_exists() { $GETENT_BIN group "$1" >/dev/null 2>&1; }

tolower() { "$TR_BIN" '[:upper:]' '[:lower:]' <<<"$1"; }

is_bad_username() {
  local candidate lc line
  candidate="$(tolower "$1")"

  for line in "${BAD_USERNAMES[@]}"; do
    lc="$(tolower "$line")"
    [[ "$candidate" == "$lc" ]] && return 0
  done

  if [[ -f "$BAD_USERNAMES_FILE" ]]; then
    while IFS= read -r line; do
      line="${line%%#*}"
      if [[ -n "$XARGS_BIN" ]]; then
        line="$(echo -n "$line" | "$XARGS_BIN" 2>/dev/null)"
      else
        line="${line#"${line%%[![:space:]]*}"}"
        line="${line%"${line##*[![:space:]]}"}"
      fi
      [[ -z "$line" ]] && continue
      lc="$(tolower "$line")"
      [[ "$candidate" == "$lc" ]] && return 0
    done < "$BAD_USERNAMES_FILE"
  fi

  return 1
}

terminate_user_processes() {
  local u="$1"
  [[ -n "$u" ]] || return 0

  if [[ -n "$LOGINCTL_BIN" ]]; then sudo "$LOGINCTL_BIN" terminate-user "$u" &>/dev/null || true; fi

  if [[ -n "$PKILL_BIN" ]]; then sudo "$PKILL_BIN" -u "$u" &>/dev/null || true; fi
  if [[ -n "$KILLALL_BIN" ]]; then sudo "$KILLALL_BIN" -u "$u" --signal TERM &>/dev/null || true; fi

  sleep 1

  local procs_alive=1
  if [[ -n "$PGREP_BIN" ]]; then
    "$PGREP_BIN" -u "$u" >/dev/null 2>&1 || procs_alive=0
  else
    ps -u "$u" >/dev/null 2>&1 || procs_alive=0
  fi

  if [[ $procs_alive -ne 0 ]]; then
    if [[ -n "$PKILL_BIN" ]]; then sudo "$PKILL_BIN" -9 -u "$u" &>/dev/null || true; fi
    if [[ -n "$KILLALL_BIN" ]]; then sudo "$KILLALL_BIN" -u "$u" --signal KILL &>/dev/null || true; fi
  fi
}

rename_user_and_home() {
  local old="$1" new="$2"
  [[ -n "$old" && -n "$new" ]] || { echo "rename_user_and_home: missing args" >&2; return 2; }
  [[ "$new" =~ ^[A-Za-z0-9_]+$ ]] || { echo "Invalid target username." >&2; return 2; }

  $GETENT_BIN passwd "$old" >/dev/null || { echo "System user '$old' does not exist." >&2; return 3; }
  if $GETENT_BIN passwd "$new" >/dev/null; then
    echo "Target user '$new' already exists." >&2; return 3
  fi
  if [[ -e "/home/$new" ]]; then
    echo "Target home '/home/$new' already exists." >&2; return 3
  fi

  terminate_user_processes "$old"
  sudo "$USERMOD_BIN" -L "$old" >/dev/null 2>&1 || true

  if ! sudo "$USERMOD_BIN" -l "$new" "$old" >/dev/null 2>&1; then
    echo "usermod -l failed; aborting." >&2
    sudo "$USERMOD_BIN" -U "$old" >/dev/null 2>&1 || true
    return 4
  fi

  if $GETENT_BIN group "$old" >/dev/null 2>&1; then
    sudo "$GROUPMOD_BIN" -n "$new" "$old" >/dev/null 2>&1 || true
  fi

  if ! sudo "$USERMOD_BIN" -d "/home/$new" -m "$new" >/dev/null 2>&1; then
    echo "usermod -d -m failed; user login renamed but home not moved." >&2
    echo "Manual intervention recommended. Aborting." >&2
    return 5
  fi

  if [[ -n "$CRONTAB_BIN" && -n "$MKTEMP_BIN" ]]; then
    local cron_tmp
    umask 077
    cron_tmp="$("$MKTEMP_BIN" -p "${TMPDIR:-/tmp}" old-cron.XXXXXX 2>/dev/null)" || cron_tmp=""
    if [[ -n "$cron_tmp" ]]; then
      if sudo "$CRONTAB_BIN" -l -u "$old" >"$cron_tmp" 2>/dev/null; then
        sudo "$CRONTAB_BIN" -u "$new" "$cron_tmp" >/dev/null 2>&1 || true
      fi
      sudo rm -f "$cron_tmp" >/dev/null 2>&1 || true
    else
      if sudo "$CRONTAB_BIN" -l -u "$old" >/tmp/.old.cron.$$ 2>/dev/null; then
        sudo "$CRONTAB_BIN" -u "$new" /tmp/.old.cron.$$ >/dev/null 2>&1
        sudo rm -f /tmp/.old.cron.$$ >/dev/null 2>&1
      fi
    fi
  fi
  if [[ -e "/var/spool/mail/$old" ]]; then
    sudo mv "/var/spool/mail/$old" "/var/spool/mail/$new" >/dev/null 2>&1 || true
  fi

  sudo "$USERMOD_BIN" -U "$new" >/dev/null 2>&1 || true
  return 0
}

main_menu() {
  echo "Greetings, and welcome to the tilde.club help desk!"
  echo ""
  echo "If you need further assistance, you can email root@tilde.club."
  echo ""
  echo "Please select from the options below:"
  echo "(pick an option by entering its corresponding number)"
  echo ""
  echo "1: SSH Key Help"
  echo "2: Password Help"
  echo "3: Change my username"
  echo "4: I'd like to leave this help desk."
  echo ""

  read -r -t 120 -p "Enter option [1-4]: " choice || { echo; echo "No input received for 2 minutes. Exiting..."; exit 1; }
  case "$choice" in
    1) ssh_key_menu ;;
    2) password_menu ;;
    3) username_menu ;;
    4) echo "Alright! Take care, tilder."; exit 0 ;;
    *) echo "Invalid choice. Exiting..."; exit 1 ;;
  esac
}

ssh_key_menu() {
  echo ""
  echo "SSH Key Help Menu"
  echo "-----------------"
  echo "1: I want to request a code to add a new SSH key to my tilde account."
  echo "2: I have a code from my email and need to redeem it to add a new SSH key."
  echo "3: Return to previous menu."
  echo ""

  read -r -t 120 -p "Enter option [1-3]: " choice || { echo; echo "No input received for 2 minutes. Exiting..."; exit 1; }
  case "$choice" in
    1) request_new_key ;;
    2) redeem_key ;;
    3) main_menu ;;
    *) echo "Invalid choice. Exiting..."; exit 1 ;;
  esac
}

password_menu() {
  echo ""
  echo "Password Help Menu"
  echo "------------------"
  echo "1: Request a password reset code"
  echo "2: Redeem a password reset code"
  echo "3: Return to previous menu."
  echo ""

  read -r -t 120 -p "Enter option [1-3]: " choice || { echo; echo "No input received for 2 minutes. Exiting..."; exit 1; }
  case "$choice" in
    1) request_password_reset ;;
    2) redeem_password_reset ;;
    3) main_menu ;;
    *) echo "Invalid choice. Exiting..."; exit 1 ;;
  esac
}

username_menu() {
  echo ""
  echo "Username Change Menu"
  echo "--------------------"
  echo "1: Request a code to change my username"
  echo "2: Redeem a username change code"
  echo "3: Return to previous menu."
  echo ""

  read -r -t 120 -p "Enter option [1-3]: " choice || { echo; echo "No input received for 2 minutes. Exiting..."; exit 1; }
  case "$choice" in
    1) request_username_change ;;
    2) redeem_username_change ;;
    3) main_menu ;;
    *) echo "Invalid choice. Exiting..."; exit 1 ;;
  esac
}

request_new_key() {
  echo ""
  printf "Please enter the email address you registered with tilde.club: "
  read -r -t 120 user_email || { echo; echo "No input received for 2 minutes. Exiting..."; exit 1; }

  [[ "$user_email" =~ ^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$ ]] \
    || { echo "That doesn't look like a valid email address. Exiting..."; exit 1; }

  user_email_esc=$(sql_escape "$user_email")
  username="$(db_scalar "SELECT username FROM users WHERE email='$user_email_esc';")"
  [ -n "$username" ] || { echo "Hmm, we don’t recognize that email. Please contact an admin or try again."; exit 1; }

  code=$(generate_code)

  db_exec "DELETE FROM requests WHERE username='$(sql_escape "$username")';"
  db_exec "INSERT INTO requests(code, username) VALUES('$(sql_escape "$code")', '$(sql_escape "$username")');"

  subject="Your tilde.club SSH key request code"
  mailbody="Hello $username,\n\nYou requested a new SSH key on tilde.club.\n\nUse this code to redeem your new SSH key:\n$code\n\nThank you and happy tildeing!"
  send_email "$user_email" "$subject" "$mailbody"

  echo "We've emailed you a code at $user_email."
  echo "Please go back to the SSH Key Help Menu and choose Redeem to complete the process."
  exit 0
}

redeem_key() {
  echo ""
  printf "Please paste the auth code you received via email: "
  read -r -t 120 auth_code || { echo; echo "No input received for 2 minutes. Exiting..."; exit 1; }

  username="$(db_scalar "SELECT username FROM requests WHERE code='$(sql_escape "$auth_code")';")"
  [ -n "$username" ] || { echo "That code is invalid or has expired. Exiting..."; exit 1; }

  echo ""
  echo "Great to see you, ~$username!"
  echo "Paste your new public SSH key (e.g., 'ssh-ed25519 AAAA...'):"
  read -r -t 120 new_key || { echo; echo "No input received for 2 minutes. Exiting..."; exit 1; }

  sudo /bin/mkdir -p "/home/$username/.ssh" >/dev/null 2>&1
  sudo /bin/chmod 700 "/home/$username/.ssh" >/dev/null 2>&1
  printf '%s\n' "$new_key" | sudo /usr/bin/tee -a "/home/$username/.ssh/authorized_keys" >/dev/null
  sudo /bin/chmod 600 "/home/$username/.ssh/authorized_keys" >/dev/null 2>&1

  db_exec "DELETE FROM requests WHERE code='$(sql_escape "$auth_code")';"

  echo ""
  echo "Your new key has been added! You can now log in using it."
  echo "Thanks for stopping by—happy tildeing!"
  exit 0
}

request_password_reset() {
  echo ""
  printf "Please enter the email address associated with your tilde.club account: "
  read -r -t 120 user_email || { echo; echo "No input received for 2 minutes. Exiting..."; exit 1; }

  [[ "$user_email" =~ ^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$ ]] \
    || { echo "That doesn't look like a valid email address. Exiting..."; exit 1; }

  user_email_esc=$(sql_escape "$user_email")
  username="$(db_scalar "SELECT username FROM users WHERE email='$user_email_esc';")"
  [ -n "$username" ] || { echo "We don't recognize that email. Please contact an admin or try again."; exit 1; }

  code=$(generate_code)

  db_exec "DELETE FROM pwdresets WHERE username='$(sql_escape "$username")';"
  db_exec "INSERT INTO pwdresets(code, username) VALUES('$(sql_escape "$code")', '$(sql_escape "$username")');"

  subject="Your tilde.club Password Reset Code"
  mailbody="Hello $username,\n\nYou requested a password reset on tilde.club.\n\nUse this code to set a new password:\n$code\n\nThanks and happy tildeing!"
  send_email "$user_email" "$subject" "$mailbody"

  echo ""
  echo "A password reset code has been emailed to $user_email."
  echo "Return to the Password Help Menu and choose 'Redeem a password reset code' to proceed."
  exit 0
}

redeem_password_reset() {
  echo ""
  printf "Please paste the password reset code you received via email: "
  read -r -t 120 auth_code || { echo; echo "No input received for 2 minutes. Exiting..."; exit 1; }

  username="$(db_scalar "SELECT username FROM pwdresets WHERE code='$(sql_escape "$auth_code")';")"
  [ -n "$username" ] || { echo "That code is invalid or has expired. Exiting..."; exit 1; }

  echo ""
  echo "Hi, ~$username!"
  printf "Enter your new password (it will not be displayed): "
  read -r -s -t 120 new_password || { echo; echo "No input received for 2 minutes. Exiting..."; exit 1; }
  echo ""
  printf "Confirm your new password: "
  read -r -s -t 120 confirm_password || { echo; echo "No input received for 2 minutes. Exiting..."; exit 1; }
  echo ""
  [ "$new_password" = "$confirm_password" ] || { echo "Passwords do not match. Exiting..."; exit 1; }

  printf '%s:%s\n' "$username" "$new_password" | sudo $CHPASSWD_BIN
  db_exec "DELETE FROM pwdresets WHERE code='$(sql_escape "$auth_code")';"

  unset new_password confirm_password

  echo ""
  echo "Your password has been reset successfully! You may now log in with your new password."
  exit 0
}

request_username_change() {
  echo ""
  printf "Please enter the email address you registered with tilde.club: "
  read -r -t 120 user_email || { echo; echo "No input received for 2 minutes. Exiting..."; exit 1; }

  [[ "$user_email" =~ ^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$ ]] \
    || { echo "That doesn't look like a valid email address. Exiting..."; exit 1; }

  old_username="$(db_scalar "SELECT username FROM users WHERE email='$(sql_escape "$user_email")';")"
  [ -n "$old_username" ] || { echo "We don't recognize that email. Please contact an admin or try again."; exit 1; }

  code=$(generate_code)

  db_exec "DELETE FROM renameRequests WHERE old_username='$(sql_escape "$old_username")';"
  db_exec "INSERT INTO renameRequests(code, old_username) VALUES('$(sql_escape "$code")', '$(sql_escape "$old_username")');"

  subject="Your tilde.club Username Change Code"
  mailbody="Hello $old_username,\n\nYou requested to change your username on tilde.club.\n\nUse this code to set a new username:\n$code\n\nThanks and happy tildeing!"
  send_email "$user_email" "$subject" "$mailbody"

  echo ""
  echo "A username change code has been emailed to $user_email."
  echo "Return to the Username Change Menu and choose 'Redeem a username change code' to proceed."
  exit 0
}

redeem_username_change() {
  echo ""
  printf "Please paste the username change code you received via email: "
  read -r -t 120 auth_code || { echo; echo "No input received for 2 minutes. Exiting..."; exit 1; }

  old_username="$(db_scalar "SELECT old_username FROM renameRequests WHERE code='$(sql_escape "$auth_code")';")"
  [ -n "$old_username" ] || { echo "That code is invalid or has expired. Exiting..."; exit 1; }

  echo ""
  echo "Hi, ~$old_username!"
  printf "Enter your desired new username (letters, digits, underscores only): "
  read -r -t 120 new_username || { echo; echo "No input received for 2 minutes. Exiting..."; exit 1; }

  [[ "$new_username" =~ ^[A-Za-z0-9_]+$ ]] || { echo "Invalid username format. Exiting..."; exit 1; }

  if is_bad_username "$new_username"; then
    echo "That username is reserved or not allowed. Please choose a different name."
    exit 1
  fi

  if id -u "$new_username" >/dev/null 2>&1; then
    echo "That new username already exists. Exiting..."; exit 1
  fi

  echo ""
  echo "Renaming user '$old_username' to '$new_username' and moving home directory..."

  if ! $GETENT_BIN passwd "$old_username" >/dev/null 2>&1; then
    echo "System user '$old_username' does not exist; cannot rename. Exiting..."; exit 1
  fi

  if ! rename_user_and_home "$old_username" "$new_username"; then
    echo ""
    echo "System rename failed; no database changes were made. Please contact an admin."
    exit 1
  fi

  db_exec "UPDATE users SET username='$(sql_escape "$new_username")' WHERE username='$(sql_escape "$old_username")';"
  db_exec "DELETE FROM renameRequests WHERE code='$(sql_escape "$auth_code")';"

  echo ""
  echo "Username successfully changed from '$old_username' to '$new_username'!"
  echo "You can now log in as '$new_username'."
  exit 0
}

main_menu
