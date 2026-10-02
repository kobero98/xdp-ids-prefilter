# scripts/env.sh — source from any repo script:
#   . "$(git rev-parse --show-toplevel 2>/dev/null || dirname "$0")/scripts/env.sh"
# Loads config.env (environment variables take precedence) and exports
# REPO_ROOT plus absolute versions of the repo-relative paths.

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export REPO_ROOT

while IFS='=' read -r key val; do
    key="${key//[[:space:]]/}"
    [[ -z "$key" || "$key" == \#* ]] && continue
    val="${val%%#*}"                       # strip trailing comment
    val="${val#"${val%%[![:space:]]*}"}"   # ltrim
    val="${val%"${val##*[![:space:]]}"}"   # rtrim
    [[ -z "${!key+x}" ]] && export "$key=$val"
done < "$REPO_ROOT/config.env"

# repo-relative paths -> absolute
for v in HSCOLLIDER DATA_DIR BUILD_DIR SLAVE_PCAP_REPLAY SLAVE_PCAP_DIR; do
    [[ "${!v}" == /* ]] || export "$v=$REPO_ROOT/${!v}"
done
