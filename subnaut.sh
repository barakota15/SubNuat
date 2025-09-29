#!/bin/bash

# ====[Get source]====
SOURCE="${BASH_SOURCE[0]}"
while [ -L "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [[ "$SOURCE" != /* ]] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" >/dev/null 2>&1 && pwd)"

# =====[Set time] ====
SECONDS=0

# =====[Colors for output]=====
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
CYAN="\e[36m"
NC='\033[0m' # No Color

# =====[Banner]=====
banner() {
    echo -e "${YELLOW}"
    echo "███████╗██╗   ██╗██████╗ ███╗   ██╗ █████╗ ██╗   ██╗████████╗"
    echo "██╔════╝██║   ██║██╔══██╗████╗  ██║██╔══██╗██║   ██║╚══██╔══╝"
    echo "███████╗██║   ██║██████╔╝██╔██╗ ██║███████║██║   ██║   ██║   "
    echo "╚════██║██║   ██║██╔══██╗██║╚██╗██║██╔══██║██║   ██║   ██║   "
    echo "███████║╚██████╔╝██████╔╝██║ ╚████║██║  ██║╚██████╔╝   ██║   "
    echo "╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚═════╝    ╚═╝   "
    echo -e "${NC}                                          ${CYAN}By Barakota15 ${NC}@v1.1"
    echo ""
}

# =====[Functions]=====
run_command() {
    local description=$1
    local command=$2
    if [ "$SILENT" = false ]; then
        echo -ne "[${YELLOW}*${NC}] $description\r"
        if [ "$DEBUG" = true ]; then
            if [[ "$description" != "Running subenum" ]]; then
                if eval "$command"; then
                    echo -ne "\033[K"
                    echo -e "[${GREEN}✓${NC}] $description"
                else
                    echo -ne "\033[K"
                    echo -e "[${RED}X${NC}] $description"
                fi
            else
                if eval "$command"; then
                    echo -ne "\033[K"
                    echo -e "[${GREEN}✓${NC}] $description"
                else
                    echo -ne "\033[K"
                    echo -e "[${GREEN}✓${NC}] $description"
                fi
            fi
        else
            if [[ "$description" != "Running subenum" ]]; then
                if eval "$command" &> /dev/null; then
                    echo -ne "\033[K"
                    echo -e "[${GREEN}✓${NC}] $description"
                else
                    echo -ne "\033[K"
                    echo -e "[${RED}X${NC}] $description"
                fi
            else
                if eval "$command" &> /dev/null; then
                    echo -ne "\033[K"
                    echo -e "[${GREEN}✓${NC}] $description"
                else
                    echo -ne "\033[K"
                    echo -e "[${GREEN}✓${NC}] $description"
                fi
            fi
        fi
    else
        eval "$command" &> /dev/null
    fi
}

run_virustotal() {
    local domain=$1
    local api_key="$API_KEY"
    local output_file="./${DOMAIN}/subs_virustotal.txt"

    if [ "$SILENT" = false ]; then
        echo -ne "[${YELLOW}*${NC}] Running VirusTotal\r"

        local response=$(curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=${api_key}&domain=${domain}")

        if echo "$response" | jq -r '.subdomains[]?' 2>/dev/null > "$output_file" && echo "$response" | jq -r '.detected_urls[].url?, .undetected_urls[][0]?' 2>/dev/null | sed -E 's#^[a-zA-Z]+://([^/]+).*#\1#; s#^//([^/]+).*#\1#' | sed 's/:.*$//' | grep -v '^$' | sort -u >> "$output_file"; then
            echo -ne "\033[K"
            echo -e "[${GREEN}✓${NC}] Running VirusTotal"
        else
            echo -ne "\033[K"
            echo -e "[${RED}X${NC}] VirusTotal failed or no subdomains found"
        fi
    else
        local response=$(curl -s "https://www.virustotal.com/vtapi/v2/domain/report?apikey=${api_key}&domain=${domain}")
        echo "$response" | jq -r '.subdomains[]?' 2>/dev/null > "$output_file"
        echo "$response" | jq -r '.detected_urls[].url?, .undetected_urls[][0]?' 2>/dev/null | sed -E 's#^[a-zA-Z]+://([^/]+).*#\1#; s#^//([^/]+).*#\1#' | sed 's/:.*$//' | grep -v '^$' | sort -u >> "$output_file"
    fi
}

show_help() {
    banner
    echo -e "${CYAN}"
    echo "SubNaut - Powerful Subdomain Enumeration Tool"
    echo ""
    echo "Usage:"
    echo "  ./subnaut.sh [flags]"
    echo ""
    echo "Flags:"
    echo "  INPUT:"
    echo "     -d, --domain <domain>                     Target domain for enumeration"
    echo "     -D, --domains <file>                      File containing list of domains"
    echo "         --ffuf <file>                         Subdomains wordlist for ffuf (default: ./wordlist/subdomains.txt)"
    echo "         --api <API key>                       VirusTotal API key"
    echo ""
    echo "  FILTER:"
    echo "     -t, --tools [tool1,tool2,...]             Specify which tools to use (Default: all)"
    echo "     -f, --filter [tool1,tool2,...]            Exclude specific tools from enumeration"
    echo ""
    echo "  OUTPUT:"
    echo "     -o, --output <file>                       Output file name (default: subdomains.txt)"
    echo "         --no-httpx                            Skip active probing with httpx"
    echo ""
    echo "  DEBUG:"
    echo "     -h, --help                                Show this help message and exit"
    echo "     -v, --version                             Show version information"
    echo "     -ls, --list-sources                       List all supported subdomain sources"
    echo "     -s, --silent                              Silent mode - only outputs subdomains without extra logs"
    echo "     -nc, --no-color                           Disable colored output"
    echo "          --debug-mode                         Enable debug mode and show detailed tool logs"
    echo ""
    echo -e "${NC}"
    exit 0
}

contains() {
    local value="$1"
    shift
    local array=("$@")

    for item in "${array[@]}"; do
        if [[ "$item" == "$value" ]]; then
            return 0  # true (found)
        fi
    done

    return 1  # false (not found)
}

# =====[Check for dependencies]=====
dependencies=(httpx jq curl)
for dep in "${dependencies[@]}"; do
    if ! command -v "$dep" &> /dev/null; then
        echo -e "[${RED}X${NC}] Dependency '$dep' is not installed. Please install it and try again."
        exit 1
    fi
done

# =====[Check for flags]=====
for arg in "$@"; do
    if [[ "$arg" == "--help" || "$arg" == "-h" || "$arg" == "--version" || "$arg" == "-v" || "$arg" == "--list-sources" || "$arg" == "-ls" || "$arg" == "--silent" || "$arg" == "-s" || "$arg" == "--no-color" || "$arg" == "-nc" || "$arg" == "--debug-mode" || "$arg" == "--api" || "$arg" == "--no-httpx" || "$arg" == "--output" || "$arg" == "-o" || "$arg" == "--domains" || "$arg" == "-D" || "$arg" == "--domain" || "$arg" == "--ffuf" || "$arg" == "-d" || "$arg" == "--tools" || "$arg" == "-t" || "$arg" == "--filter" || "$arg" == "-f" ]]; then
        continue
    else
        if [[ "$arg" == -* ]]; then
            echo -e "[${RED}X${NC}] Invalid argument: '$arg'. Use --help or -h for usage information."
        fi
    fi
done

# =====[Check debug flags]=====
for arg in "$@"; do
    if [[ "$arg" == "--help" || "$arg" == "-h" ]]; then
        show_help
    fi
done

for arg in "$@"; do
    if [[ "$arg" == "--version" || "$arg" == "-v" ]]; then
        echo -e "${CYAN}SubNaut version 1.1 by Barakota15${NC}"
        exit 0
    fi
done

for arg in "$@"; do
    if [[ "$arg" == "--list-sources" || "$arg" == "-ls" ]]; then
        echo -e "${CYAN}Available Subdomain Sources:${NC}"
        echo "  - subfinder"
        echo "  - assetfinder"
        echo "  - knock"
        echo "  - findomain"
        echo "  - subenum"
        echo "  - VirusTotal"
        echo "  - ffuf"
        exit 0
    fi
done

for arg in "$@"; do
    if [[ "$arg" == "--silent" || "$arg" == "-s" ]]; then
        SILENT=true
        break
    else
        SILENT=false
    fi
done

for arg in "$@"; do
    if [[ "$arg" == "--no-color" || "$arg" == "-nc" ]]; then
        GREEN='\033[0m'
        RED='\033[0m'
        YELLOW='\033[0m'
        CYAN='\033[0m'
        NC='\033[0m'
        break
    fi
done

DEBUG=false
for arg in "$@"; do
    if [[ "$arg" == "--debug-mode" ]]; then
        DEBUG=true
    fi
done

# =====[Check output flags]=====
OUTPUT_FILE="subdomains.txt"

for ((i=0; i <= $#; i++)); do
    arg="${!i}"
    next_index=$((i + 1))
    next_arg="${!next_index}"

    if [[ "$arg" == "--output" || "$arg" == "-o" ]]; then
        if [[ -n "$next_arg" && "$next_arg" != -* ]]; then
            OUTPUT_FILE="$next_arg"
            break
        else
            echo -e "[${RED}X${NC}] No output file specified after $arg."
            exit 1
        fi
    fi
done

for arg in "$@"; do
    if [[ "$arg" == "--no-httpx" ]]; then
        HTTPX=false
        break
    else
        HTTPX=true
    fi
done

# ====[Check input flags]=====
declare -a DOMAIN_LIST

for ((i=0; i <= $#; i++)); do
    arg="${!i}"
    next_index=$((i + 1))
    next_arg="${!next_index}"

    case "$arg" in
        -d|--domain)
            if [[ -n "$next_arg" && "$next_arg" != -* ]]; then
                if [[ "$next_arg" =~ ^[a-zA-Z0-9.-]+$ && "$next_arg" == *.* ]]; then
                    DOMAIN_LIST+=("$next_arg")
                    continue
                else
                    echo -e "[${RED}X${NC}] Invalid domain format: '$next_arg'."
                    exit 1
                fi
            else
                echo -e "[${RED}X${NC}] No domain specified after $arg."
                exit 1
            fi
            ;;

        -D|--domains)
            if [[ -n "$next_arg" && "$next_arg" != -* ]]; then
                DOMAIN_FILE="$next_arg"
                if [ ! -f "$DOMAIN_FILE" ]; then
                    echo -e "[${RED}X${NC}] Domain file '$DOMAIN_FILE' does not exist."
                    exit 1
                elif [ ! -r "$DOMAIN_FILE" ]; then
                    echo -e "[${RED}X${NC}] Domain file '$DOMAIN_FILE' is not readable."
                    exit 1
                else
                    cat "$DOMAIN_FILE" | sort -u | tee "tmp_$DOMAIN_FILE" &> /dev/null
                fi

                while IFS= read -r line || [ -n "$line" ]; do
                    line="${line#"${line%%[![:space:]]*}"}"
                    line="${line%"${line##*[![:space:]]}"}"
                    if [[ "$line" =~ ^[a-zA-Z0-9.-]+$ && "$line" == *.* ]]; then
                        DOMAIN_LIST+=("$line")
                    else
                        echo -e "[${RED}X${NC}] Invalid domain in file: '$line'"
                    fi
                done < "tmp_$DOMAIN_FILE"
                rm -f "tmp_$DOMAIN_FILE" &> /dev/null
                continue
            else
                echo -e "[${RED}X${NC}] No domain file specified after $arg"
                exit 1
            fi
            ;;

        *)
            ;;
    esac
done

for ((i=0; i <= $#; i++)); do
    arg="${!i}"
    next_index=$((i + 1))
    next_arg="${!next_index}"
    
    if [[ "$arg" == "--api" ]]; then
        API_KEY="$next_arg"
        if [ -z "$API_KEY" ]; then
            echo -e "[${RED}X${NC}] No API key specified after $arg"
            exit 1
        fi
        break
    fi
done

# ====[Check if DOMAIN_LIST is empty]=====
if [ ${#DOMAIN_LIST[@]} -eq 0 ]; then
    echo -e "[${RED}X${NC}] No valid domains provided."
    exit 1
fi

# ====[Check filter flag]====
VALID_TOOLS=("subfinder" "assetfinder" "virustotal" "knock" "findomain" "subenum")
declare -a FILTERED_TOOLS
declare -a TOOLS

for ((i=0; i <= $#; i++)); do
    arg="${!i}"
    next_index=$((i + 1))
    next_arg="${!next_index}"
    if [[ "$arg" == "--filter" || "$arg" == "-f" ]]; then
        FILTER_TOOL="$next_arg"
        if [[ -z "$FILTER_TOOL" && "$FILTER_TOOL" != -* ]]; then
            echo -e "[${RED}X${NC}] No filter tool specified after $arg."
            exit 1
        fi
        
        IFS=',' read -ra FILTER_TOOLS_TMP <<< "$FILTER_TOOL"
        for tool in "${FILTER_TOOLS_TMP[@]}"; do
            tool="${tool#"${tool%%[![:space:]]*}"}"
            tool="${tool%"${tool##*[![:space:]]}"}"
            FILTERED_TOOLS+=("$tool")

            valid=false
            for valid_tool in "${VALID_TOOLS[@]}"; do
                if [[ "$tool" == "$valid_tool" ]]; then
                    valid=true
                    break
                fi
            done

            if [[ "$valid" == false ]]; then
                echo -e "[${RED}X${NC}] Invalid filter tool: '$tool'."
                echo -e "[${YELLOW}i${NC}] Valid tools are: ${VALID_TOOLS[*]}"
                exit 1
            fi
        done
    fi
done

for ((i=0; i <= $#; i++)); do
    arg="${!i}"
    next_index=$((i + 1))
    next_arg="${!next_index}"

    if [[ "$arg" == "--tools" || "$arg" == "-t" ]]; then
        TOOL="$next_arg"
        if [[ -z "$TOOL" && "$TOOL" != -* ]]; then
            echo -e "[${RED}X${NC}] No tool specified after $arg."
            exit 1
        fi
        
        IFS=',' read -ra TOOLS_TMP <<< "$TOOL"
        for tool in "${TOOLS_TMP[@]}"; do
            tool="${tool#"${tool%%[![:space:]]*}"}"
            tool="${tool%"${tool##*[![:space:]]}"}"
            TOOLS+=("$tool")

            valid=false
            for valid_tool in "${VALID_TOOLS[@]}"; do
                if [[ "$tool" == "$valid_tool" ]]; then
                    valid=true
                    break
                fi
            done

            if [[ "$valid" == false ]]; then
                NOTVALID_TOOLS+=("$tool")
            fi
        done
        if [[ "${#NOTVALID_TOOLS[@]}" -gt 0 ]]; then
            echo -e "[${RED}X${NC}] Invalid tool: '${NOTVALID_TOOLS[@]}'."
            echo -e "[${YELLOW}i${NC}] Valid tools are: ${VALID_TOOLS[*]}"
            exit 1
        fi
    fi
done

if [ ${#TOOLS[@]} -eq 0 ]; then
    TOOLS=("${VALID_TOOLS[@]}")
fi

for ((i=0; i <= $#; i++)); do
    arg="${!i}"
    next_index=$((i + 1))
    next_arg="${!next_index}"

    if [[ "$arg" == "--ffuf" ]]; then
        if [[ -n "$next_arg" && "$next_arg" != -* ]]; then
            FFUF_WORDLIST="$next_arg"
            if [ ! -f "$FFUF_WORDLIST" ]; then
                echo -e "[${RED}X${NC}] Wordlist file '$FFUF_WORDLIST' does not exist."
                exit 1
            elif [ ! -r "$FFUF_WORDLIST" ]; then
                echo -e "[${RED}X${NC}] Wordlist file '$FFUF_WORDLIST' is not readable."
                exit 1
            else
                cat "$FFUF_WORDLIST" | sort -u | tee "$FFUF_WORDLIST" &> /dev/null
            fi
        else
            FFUF_WORDLIST="$SCRIPT_DIR/wordlist/subdomains.txt"
        fi
        TOOLS+=("ffuf")
        break
    fi
done

if ! contains "ffuf" "${TOOLS[@]}"; then
    FILTERED_TOOLS+=("ffuf")
fi

declare -a FILTERED_TOTAL
for item in "${TOOLS[@]}"; do
    i="${item}"
    if contains "$item" "${TOOLS[@]}" && ! contains "$item" "${FILTERED_TOOLS[@]}"; then
        FILTERED_TOTAL+=("$i")
    fi
done
if [ ${#FILTERED_TOTAL[@]} -eq 0 ]; then
    echo -e "[${RED}X${NC}] All tools have been filtered out. Nothing to run."
    exit 1
fi

# =====[Check for dependencies]=====
for dep in "${FILTERED_TOTAL[@]}"; do
    if ! command -v "$dep" &> /dev/null; then
        if [ "$dep" == "virustotal" ]; then
            if [ -z "$API_KEY" ]; then
                echo -e "[${RED}X${NC}] VirusTotal API key is required but not provided. Please provide an API key or filter out 'virustotal' and try again."
                exit 1
            fi
            continue
        fi
        echo -e "[${RED}X${NC}] Dependency '$dep' is not installed. Please install it or filter it out and try again."
        exit 1
    fi
done

# =====[Display banner]=====
if [ "$SILENT" = false ]; then
    banner
fi

# ====[Display configurations]====
if [ "$SILENT" = false ]; then
    if [ ${#FILTERED_TOTAL[@]} -gt 0 ]; then
        echo -e "[${CYAN}i${NC}] Using tools: ${YELLOW}${FILTERED_TOTAL[*]}${NC}"
    else
        echo -e "[${CYAN}i${NC}] Using tools: ${YELLOW}None${NC}"
    fi
    if [ ${#FILTERED_TOOLS[@]} -gt 0 ]; then
        echo -e "[${CYAN}i${NC}] Filtering out tools: ${YELLOW}${FILTERED_TOOLS[*]}${NC}"
    else
        echo -e "[${CYAN}i${NC}] Filtering out tools: ${YELLOW}None${NC}"
    fi
    if [ ${#DOMAIN_LIST[@]} -gt 0 ]; then
        echo -e "[${CYAN}i${NC}] Domains: ${YELLOW}${DOMAIN_LIST[*]}${NC}"
    else
        echo -e "[${CYAN}i${NC}] Domains: ${YELLOW}None${NC}"
    fi
    echo -e "[${CYAN}i${NC}] Output File: ${YELLOW}${OUTPUT_FILE}${NC}"
    echo -e "[${CYAN}i${NC}] Using HTTPX: ${YELLOW}${HTTPX}${NC}"
    if [[ $GREEN == '\033[0;32m' ]]; then
        echo -e "[${CYAN}i${NC}] Display Colors: ${YELLOW}true${NC}"
    else
        echo -e "[${CYAN}i${NC}] Display Colors: ${YELLOW}false${NC}"
    fi
    if contains "ffuf" "${FILTERED_TOTAL[@]}"; then
        echo -e "[${CYAN}i${NC}] FFUF Wordlist: ${YELLOW}${FFUF_WORDLIST}${NC}"
    fi
    echo ""
fi

# ====[Start script]====
for DOMAIN in "${DOMAIN_LIST[@]}"; do
    mkdir "$DOMAIN" &> /dev/null
    if [ "$SILENT" = false ]; then
        echo -e "[${CYAN}*${NC}] Starting subdomain enumeration for: ${YELLOW}$DOMAIN${NC}"
        echo ""
    fi

    # =====[Tools Execution]=====
    if contains "subfinder" "${FILTERED_TOTAL[@]}"; then
        run_command "Running subfinder" \
            "subfinder -d \"$DOMAIN\" --all --recursive -o ./${DOMAIN}/subs_subfinder.txt"
    fi

    if contains "assetfinder" "${FILTERED_TOTAL[@]}"; then
        run_command "Running assetfinder" \
            "echo \"$DOMAIN\" | assetfinder --subs-only > ./${DOMAIN}/subs_assetfinder.txt"
    fi

    if contains "virustotal" "${FILTERED_TOTAL[@]}"; then
        run_virustotal "$DOMAIN"
    fi

    if contains "knock" "${FILTERED_TOTAL[@]}"; then
        run_command "Running knock" \
            "knock -d \"$DOMAIN\" --recon"
        
        # =====[Extract domains from JSON if found - Without echo]=====
        JSON_FILE=$(ls ${DOMAIN}*.json 2>/dev/null | head -n 1)

        if [ -n "$JSON_FILE" ]; then
            jq -r '..|.domain? // empty' "$JSON_FILE" > ./${DOMAIN}/subs_knock.txt 2>/dev/null
        fi
        rm -f ${DOMAIN}*.json
    fi

    if contains "findomain" "${FILTERED_TOTAL[@]}"; then
        run_command "Running findomain" \
            "findomain -t \"$DOMAIN\" -u ./${DOMAIN}/subs_findomain.txt"
    fi

    if contains "subenum" "${FILTERED_TOTAL[@]}"; then
        run_command "Running subenum" \
            "subenum -d \"$DOMAIN\" -u wayback,crt,abuseipdb,Amass -o ./${DOMAIN}/subs_subenum.txt"
    fi

    if contains "ffuf" "${FILTERED_TOTAL[@]}"; then
        run_command "Running ffuf" \
            "ffuf -w \"$FFUF_WORDLIST\" -u \"https://FUZZ.$DOMAIN\" -mc 200,301,302,403 -H \"X-Forwarded-For: 127.0.0.1\" -H \"X-Forwarded-Host: 127.0.0.1\" -o ./${DOMAIN}/ffuf_out.json -of json && jq -r '.results[].url' ./${DOMAIN}/ffuf_out.json > ./${DOMAIN}/subs_ffuf.txt && rm ./${DOMAIN}/ffuf_out.json"
    fi

    echo ""

    # =====[Combine all subs_*.txt into subdomains.txt with echo]=====
    run_command "Combining results into ./${DOMAIN}/${OUTPUT_FILE}" \
        "cat ./${DOMAIN}/subs_*.txt | sort -u | tee ./${DOMAIN}/${OUTPUT_FILE}"

    # =====[Run httpx on the subdomains file and store only status 200 with echo]=====
    if [ "$HTTPX" = true ]; then
        run_command "Probing active subdomains with httpx (200, 301, 302)" \
            "cat ./${DOMAIN}/${OUTPUT_FILE} | httpx -mc 200,301,302 -o ./${DOMAIN}/active_${OUTPUT_FILE}"

        run_command "Probing active subdomains with httpx (403 Forbidden)" \
            "cat ./${DOMAIN}/${OUTPUT_FILE} | httpx -mc 403 -o ./${DOMAIN}/forbidden_${OUTPUT_FILE}"
    fi

    # =====[Clean up temporary subs_* files silently]=====
    echo ""
    rm -f ./${DOMAIN}/subs_*.txt resume* &> /dev/null

    # =====[Show results]=====
    if [ "$SILENT" = true ]; then
        cat ./${DOMAIN}/${OUTPUT_FILE} | sort -u
    fi
done

# =====[Calculate time]=====
total_time=$SECONDS
minutes=$((total_time / 60))
seconds=$((total_time % 60))
hours=$((minutes / 60))
minutes=$((minutes % 60))

# ====[End Statment]====
if [ "$SILENT" = false ]; then
    if [ $hours -gt 0 ]; then
        echo -e "\n[${GREEN}✓${NC}] Subdomain enumeration completed in ${hours}h ${minutes}m ${seconds}s."
        exit 0
    elif [ $minutes -gt 0 ]; then
        echo -e "\n[${GREEN}✓${NC}] Subdomain enumeration completed in ${minutes}m ${seconds}s."
        exit 0
    else
        echo -e "\n[${GREEN}✓${NC}] Subdomain enumeration completed in ${seconds}s."
        exit 0
    fi
fi
