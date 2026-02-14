#!/usr/bin/env bash

DB_PATH="/home/help/helpdesk.db"

add_user() {
  local username="$1"
  local email="$2"

  user_count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM users WHERE username='$username';")
  if [ "$user_count" -gt 0 ]; then
    sqlite3 "$DB_PATH" "UPDATE users SET email='$email' WHERE username='$username';"
    echo "Updated user $username with email $email"
  else
    sqlite3 "$DB_PATH" "INSERT INTO users(username, email) VALUES('$username', '$email');"
    echo "Added user $username with email $email"
  fi
}

delete_user() {
  local username="$1"

  user_count=$(sqlite3 "$DB_PATH" "SELECT COUNT(*) FROM users WHERE username='$username';")
  if [ "$user_count" -gt 0 ]; then
    sqlite3 "$DB_PATH" "DELETE FROM users WHERE username='$username';"
    echo "Deleted user $username"
  else
    echo "User $username not found in database."
  fi
}

case "$1" in
  add)
    if [ $# -ne 3 ]; then
      echo "Usage: $0 add <username> <email>"
      exit 1
    fi
    add_user "$2" "$3"
    ;;
  del)
    if [ $# -ne 2 ]; then
      echo "Usage: $0 del <username>"
      exit 1
    fi
    delete_user "$2"
    ;;
  *)
    echo "Usage: $0 <command> [arguments]"
    echo ""
    echo "Commands:"
    echo "  add <username> <email>   Add or update a user"
    echo "  del <username>           Delete a user from the database"
    exit 0
    ;;
esac
