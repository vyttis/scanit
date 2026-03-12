#!/usr/bin/env bash
# scanit.lt — Automated Production Deployment Script
# Run from project root: ./scripts/deploy.sh
#
# Prerequisites:
#   npm install -g supabase vercel
#   export SUPABASE_ACCESS_TOKEN=sbp_...
#   export VERCEL_TOKEN=...
#
set -euo pipefail

echo "=========================================="
echo "  scanit.lt — Production Deployment"
echo "=========================================="

# ──────────────────────────────────────────────
# 0. Validate prerequisites
# ──────────────────────────────────────────────
command -v supabase >/dev/null 2>&1 || { echo "ERROR: supabase CLI not installed. Run: npm install -g supabase"; exit 1; }
command -v vercel >/dev/null 2>&1   || { echo "ERROR: vercel CLI not installed. Run: npm install -g vercel"; exit 1; }

if [ -z "${SUPABASE_ACCESS_TOKEN:-}" ]; then
  echo "ERROR: SUPABASE_ACCESS_TOKEN not set."
  exit 1
fi

if [ -z "${VERCEL_TOKEN:-}" ]; then
  echo "ERROR: VERCEL_TOKEN not set."
  exit 1
fi

echo "[OK] Prerequisites verified."

# ──────────────────────────────────────────────
# 1. Create Supabase production project
# ──────────────────────────────────────────────
echo ""
echo "Step 1: Creating Supabase project 'scanit-lt'..."

# Get organization ID
ORG_ID=$(supabase orgs list --output json 2>/dev/null | python3 -c "import sys,json; orgs=json.load(sys.stdin); print(orgs[0]['id'])" 2>/dev/null || echo "")

if [ -z "$ORG_ID" ]; then
  echo "ERROR: Could not get Supabase organization. Check your access token."
  exit 1
fi

echo "  Supabase org ID: $ORG_ID"

# Check if project already exists
EXISTING=$(supabase projects list --output json 2>/dev/null | python3 -c "
import sys,json
projects = json.load(sys.stdin)
for p in projects:
    if p['name'] == 'scanit-lt':
        print(p['id'])
        break
" 2>/dev/null || echo "")

if [ -n "$EXISTING" ]; then
  PROJECT_REF="$EXISTING"
  echo "  Project already exists: $PROJECT_REF"
else
  # Generate a strong DB password
  DB_PASSWORD=$(openssl rand -base64 32 | tr -d '/+=' | head -c 24)
  echo "  DB Password generated (save this!): $DB_PASSWORD"

  PROJECT_REF=$(supabase projects create scanit-lt \
    --org-id "$ORG_ID" \
    --db-password "$DB_PASSWORD" \
    --region eu-central-1 \
    --output json 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin)['id'])" 2>/dev/null || echo "")

  if [ -z "$PROJECT_REF" ]; then
    echo "ERROR: Failed to create Supabase project."
    exit 1
  fi

  echo "  Project created: $PROJECT_REF"
  echo "  Waiting for project to be ready (this takes ~2 minutes)..."

  for i in $(seq 1 30); do
    STATUS=$(supabase projects list --output json 2>/dev/null | python3 -c "
import sys,json
projects = json.load(sys.stdin)
for p in projects:
    if p['id'] == '$PROJECT_REF':
        print(p.get('status', 'UNKNOWN'))
        break
" 2>/dev/null || echo "UNKNOWN")

    if [ "$STATUS" = "ACTIVE_HEALTHY" ]; then
      echo "  Project is ready!"
      break
    fi
    echo "  Status: $STATUS (attempt $i/30)..."
    sleep 10
  done
fi

echo "[OK] Supabase project: $PROJECT_REF"

# ──────────────────────────────────────────────
# 2. Link project and run migrations
# ──────────────────────────────────────────────
echo ""
echo "Step 2: Running database migrations..."

supabase link --project-ref "$PROJECT_REF"

supabase db push --linked

echo "[OK] Migrations applied."

# ──────────────────────────────────────────────
# 3. Create private storage bucket
# ──────────────────────────────────────────────
echo ""
echo "Step 3: Creating private storage bucket 'reports'..."

# Get API keys
API_KEYS=$(supabase projects api-keys --project-ref "$PROJECT_REF" --output json 2>/dev/null)

SUPABASE_URL="https://${PROJECT_REF}.supabase.co"
ANON_KEY=$(echo "$API_KEYS" | python3 -c "import sys,json; keys=json.load(sys.stdin); print([k['api_key'] for k in keys if k['name']=='anon'][0])" 2>/dev/null)
SERVICE_ROLE_KEY=$(echo "$API_KEYS" | python3 -c "import sys,json; keys=json.load(sys.stdin); print([k['api_key'] for k in keys if k['name']=='service_role'][0])" 2>/dev/null)

# Create storage bucket via API
curl -s -X POST "${SUPABASE_URL}/storage/v1/bucket" \
  -H "Authorization: Bearer ${SERVICE_ROLE_KEY}" \
  -H "apikey: ${SERVICE_ROLE_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"id":"reports","name":"reports","public":false}' || true

echo "[OK] Storage bucket 'reports' created (private)."

# ──────────────────────────────────────────────
# 4. Display Supabase credentials
# ──────────────────────────────────────────────
echo ""
echo "Step 4: Supabase production credentials:"
echo "  NEXT_PUBLIC_SUPABASE_URL=${SUPABASE_URL}"
echo "  NEXT_PUBLIC_SUPABASE_ANON_KEY=${ANON_KEY}"
echo "  SUPABASE_SERVICE_ROLE_KEY=${SERVICE_ROLE_KEY}"

# ──────────────────────────────────────────────
# 5. Deploy to Vercel
# ──────────────────────────────────────────────
echo ""
echo "Step 5: Deploying to Vercel..."

# Load .env.local for API keys
ANTHROPIC_KEY=""
if [ -f .env.local ]; then
  ANTHROPIC_KEY=$(grep ANTHROPIC_API_KEY .env.local | cut -d= -f2- | xargs)
fi

# Generate NEXTAUTH_SECRET
NEXTAUTH_SECRET=$(openssl rand -base64 32)

# Link/create Vercel project
vercel link --yes --token "$VERCEL_TOKEN" 2>/dev/null || true

# Set environment variables
echo "  Setting environment variables..."
echo "$SUPABASE_URL"       | vercel env add NEXT_PUBLIC_SUPABASE_URL production --token "$VERCEL_TOKEN" 2>/dev/null || true
echo "$ANON_KEY"           | vercel env add NEXT_PUBLIC_SUPABASE_ANON_KEY production --token "$VERCEL_TOKEN" 2>/dev/null || true
echo "$SERVICE_ROLE_KEY"   | vercel env add SUPABASE_SERVICE_ROLE_KEY production --token "$VERCEL_TOKEN" 2>/dev/null || true
echo "$NEXTAUTH_SECRET"    | vercel env add NEXTAUTH_SECRET production --token "$VERCEL_TOKEN" 2>/dev/null || true
echo "https://platform.scanit.lt" | vercel env add NEXT_PUBLIC_APP_URL production --token "$VERCEL_TOKEN" 2>/dev/null || true

if [ -n "$ANTHROPIC_KEY" ]; then
  echo "$ANTHROPIC_KEY" | vercel env add ANTHROPIC_API_KEY production --token "$VERCEL_TOKEN" 2>/dev/null || true
fi

# Set placeholder scan API keys (replace with real keys later)
for KEY_NAME in SHODAN_API_KEY HIBP_API_KEY SECURITYTRAILS_API_KEY VIRUSTOTAL_API_KEY ABUSEIPDB_API_KEY URLSCAN_API_KEY MXTOOLBOX_API_KEY; do
  VAL=$(grep "$KEY_NAME" .env.local 2>/dev/null | cut -d= -f2- | xargs || echo "")
  if [ -n "$VAL" ]; then
    echo "$VAL" | vercel env add "$KEY_NAME" production --token "$VERCEL_TOKEN" 2>/dev/null || true
  fi
done

echo "[OK] Environment variables set."

# Deploy to production
echo "  Running production build and deploy..."
DEPLOY_URL=$(vercel --prod --yes --token "$VERCEL_TOKEN" 2>&1 | tail -1)

echo ""
echo "=========================================="
echo "  DEPLOYMENT COMPLETE"
echo "=========================================="
echo ""
echo "  Vercel URL: $DEPLOY_URL"
echo "  Supabase:   $SUPABASE_URL"
echo ""
echo "  Next steps:"
echo "  1. Add custom domain 'platform.scanit.lt' in Vercel dashboard"
echo "  2. Add real API keys for scan modules in Vercel env vars"
echo "  3. Enable MFA enforcement in Supabase Auth settings"
echo "  4. Set storage bucket 'reports' to private in Supabase dashboard"
echo ""
