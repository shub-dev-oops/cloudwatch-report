TEAM_ID="<team-id>"
CHANNEL_ID="<channel-id>"
API_URL="https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/collect?authKey=<YOUR_SHARED_SECRET>"

EXPIRE=$(date -u -d '+55 minutes' +%Y-%m-%dT%H:%M:%SZ)

curl -s -X POST https://graph.microsoft.com/v1.0/subscriptions \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{
    \"changeType\": \"created\",
    \"resource\": \"/teams/$TEAM_ID/channels/$CHANNEL_ID/messages\",
    \"notificationUrl\": \"$API_URL\",
    \"expirationDateTime\": \"$EXPIRE\"
  }" | jq
