import os
import pandas as pd
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from datetime import datetime

# ensure slack bot token is set as environment variable
slack_token = os.getenv('SLACK_BOT_TOKEN')
if not slack_token:
    raise ValueError("SLACK_BOT_TOKEN environment variable not set")

client = WebClient(token=slack_token)

# Define the channels you are looking for
channels = ["test-channel-1", "test-channel-2"]

# Function to search messages in a channel
def search_messages(channel_id):
    messages = []
    try:
        response = client.conversations_history(channel=channel_id)
        messages.extend(response['messages'])
        while response['has_more']:
            response = client.conversations_history(channel=channel_id, cursor=response['response_metadata']['next_cursor'])
            messages.extend(response['messages'])
        return messages
    except SlackApiError as e:
        print(f"Error fetching messages from channel {channel_id}: {e.response['error']}")
        return []

# Function to extract alert information from messages
def extract_alerts(messages, channel_id):
    alerts = []
    for message in messages:
        text = message.get('text', '')
        if "Alert ID" in text and "Alert Name" in text:
            try:
                alert_id = text.split("Alert ID:")[1].split("\n")[0].strip()
                if alert_id.startswith(("EXAMPLE-1", "EXAMPLE-2")): # change as needed for desired alert IDs
                    alert_name = text.split("Alert Name:")[1].strip()
                    timestamp = message['ts']
                    readable_timestamp = datetime.fromtimestamp(float(timestamp)).strftime('%Y-%m-%d %H:%M:%S')
                    message_link = f"https://app.slack.com/client/T00000000/{channel_id}/{timestamp}"
                    alerts.append({
                        'alert_id': alert_id,
                        'alert_name': alert_name,
                        'timestamp': readable_timestamp,
                        'message_link': message_link
                    })
            except IndexError:
                continue
    return alerts

# Function to write alerts to a CSV file
def write_to_csv(alerts, file_name='alerts.csv'):
    df = pd.DataFrame(alerts)
    df.to_csv(file_name, index=False)

def main():
    all_alerts = []
    for channel_name in channels:
        # Get the channel ID
        try:
            response = client.conversations_list()
            channel_id = next((channel['id'] for channel in response['channels'] if channel['name'] == channel_name), None)
            if not channel_id:
                print(f"Channel {channel_name} not found.")
                continue
        except SlackApiError as e:
            print(f"Error fetching channel list: {e.response['error']}")
            continue

        # Fetch messages and extract alerts
        messages = search_messages(channel_id)
        alerts = extract_alerts(messages, channel_id)
        all_alerts.extend(alerts)

    if all_alerts:
        write_to_csv(all_alerts)
        print(f"Found and wrote {len(all_alerts)} alerts to CSV.")
    else:
        print("No alerts found in the specified channels.")

if __name__ == "__main__":
    main()
